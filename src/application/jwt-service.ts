import { WithId} from "mongodb";
import jwt from 'jsonwebtoken';
import {UserAccountDBType, UserMongoDbType} from "../types/users/inputUsersType";


// const secretKey = 'your_secret_key';
const refreshTokenSecret = 'your_refresh_token_secret';
// const tokenExpiration = '1h';  // Время жизни access токена
const refreshTokenExpiration = '20s';  // Время жизни refresh токена


export const jwtService={


    async  createAccessToken(user:WithId<UserAccountDBType>){
        const token = jwt.sign({userId:user._id}, process.env.JWT_SECRET as string, {expiresIn: '10s'})
        return token

    },
    async createRefreshToken(user: WithId<UserAccountDBType>) {
        return jwt.sign({ userId: user._id }, refreshTokenSecret, { expiresIn: refreshTokenExpiration });
    },

    async getUserIdByToken(token:string){
        try {
            const result: any = jwt.verify(token, process.env.JWT_SECRET as string)
            return  result.userId
        }catch (error){
            return null
        }
    },
    async verifyRefreshToken(token: string) {
        return jwt.verify(token, refreshTokenSecret);
    },
    async getUserIdByRefreshToken(token: string) {
        try {
            const result: any = await this.verifyRefreshToken(token);
            return result.userId;
        } catch (error) {
            return null;
        }
    }

}