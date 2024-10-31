import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { LoginUserDto, RegisterUserDto } from './dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {

    constructor(
        private readonly jwtService: JwtService
    ) {
        super();
    }
    
    private readonly logger = new Logger('AuthService');
    
    onModuleInit() {
        this.$connect();
        this.logger.log('MongoDB connected');
    }

    async signJWT(payload: JwtPayload) {
        return this.jwtService.sign(payload);
    }

    async verifyToken(token: string) {

        try {
            const {sub, iat, exp, ...user} = this.jwtService.verify(token, {
                secret: envs.jwtSecret
            });

            return {
                user: user,
                token: await this.signJWT(user),
            }
        } catch (error) {
            throw new RpcException({
                status: 401, //Unauthorized
                message: 'Invalid token'
            });
        }
    }

    async registerUser(registerUserDto: RegisterUserDto) {

        const {name, email, password} = registerUserDto;

        try {

            const user = await this.user.findUnique({
                where: {
                    email
                }
            });

            if (user) {
                throw new RpcException({
                    status: 400,
                    message: 'User already exists'
                });
            }

            const newUser = await this.user.create({
                data: {
                    email: email,
                    password: bcrypt.hashSync(password, 10),
                    name: name
                }
            });

            const {password: __, ...restWithoutPassword} = newUser;

            return {
                user: restWithoutPassword,
                token: await this.signJWT(restWithoutPassword)
            }
            
        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            });
        }
    }

    async loginUser(loginUserDto: LoginUserDto) {
        const {email, password} = loginUserDto;

        try {

            const user = await this.user.findUnique({
                where: {email}
            });
            if (!user) {
                throw new RpcException({
                    status: 400,
                    message: 'Invalid credentials'
                });
            }

            const isPasswordValid = bcrypt.compareSync(password, user.password);
            if (!isPasswordValid) {
                throw new RpcException({
                    status: 400,
                    message: 'User/Password not valid'
                });
            }

            const {password: __, ...restWithoutPassword} = user;

            return {
                user: restWithoutPassword,
                token: await this.signJWT(restWithoutPassword)
            }
            
        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            });
        }
    }

}
