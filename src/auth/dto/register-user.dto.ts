import { IsEmail, IsNotEmpty, IsString, IsStrongPassword } from "class-validator";

export class RegisterUserDto {

    @IsString()
    name: string;

    @IsEmail()
    @IsNotEmpty()
    email: string;

    @IsString()
    @IsStrongPassword()
    password: string;
}