import { Response, Request, Router } from "express";
import { UsersService } from "../domain/users-service";
import { RequestWithBody } from "../types/common";
import {LoginUserType, UserAccountDBType} from "../types/users/inputUsersType";
import { jwtService } from "../application/jwt-service";
import { WithId } from "mongodb";
import { CurrentUserType } from "../types/users/outputUserType";
import {
    authMiddlewareBearer, authMiddlewareRefresh,
    emailResendingValidation,
    registrationValidation,
} from "../middlewares/auth/auth-middleware";
import {loginzationValidation} from "../validators/user-validators";

export const authRouter = Router({});

authRouter.post('/login', loginzationValidation(), async (req: RequestWithBody<LoginUserType>, res: Response) =>{
    const user:WithId<UserAccountDBType> | null = await UsersService.checkCredentials(req.body.loginOrEmail, req.body.password)
    if(!user){
        res.sendStatus(401)
        return
    }
    const token = await jwtService.createAccessToken(user)
    const refreshToken = await jwtService.createRefreshToken(user)
    res.cookie('refreshToken', refreshToken, {httpOnly: true, secure: true,})
    res.status(200).send({ accessToken: token });
})

authRouter.post('/refresh-token', authMiddlewareRefresh, async (req: Request, res: Response) => {
    const oldRefreshToken = req.cookies?.refreshToken;
    const user = req.userDto as WithId<UserAccountDBType>;

    if (!oldRefreshToken || !user) {
        res.sendStatus(401);
        return;
    }

    const newAccessToken = await jwtService.createAccessToken(user);
    const newRefreshToken = await jwtService.createRefreshToken(user);

    // Добавляем старый refresh токен в черный список
    await jwtService.revokeRefreshToken(oldRefreshToken);

    res.cookie('refreshToken', newRefreshToken, { httpOnly: true, secure: true });
    res.status(200).send({ accessToken: newAccessToken });
})

authRouter.post('/logout', authMiddlewareRefresh, async (req: Request, res: Response) => {
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
        res.sendStatus(401);
        return;
    }

    try {
        await jwtService.revokeRefreshToken(refreshToken);
        res.clearCookie('refreshToken');
        res.sendStatus(204); // No Content
    } catch (error) {
        res.sendStatus(401); // Unauthorized
    }
});

authRouter.get('/me', authMiddlewareBearer, async (req: Request, res: Response<CurrentUserType>) => {
    const user = req.userDto;
    return res.status(200).json({
        "login": user.accountData.userName,
        "email": user.accountData.email,
        "userId": user._id.toString()
    });
});

authRouter.post('/registration', registrationValidation(),  async (req: Request, res: Response) => {

    const result = await UsersService.createUnconfirmedUser(req.body.login, req.body.email, req.body.password);
    if(!result){
        res.sendStatus(500)
        return
    }
    res.sendStatus(204)
});

authRouter.post('/registration-confirmation',  async (req: Request, res: Response) => {
    const result = await UsersService.confirmEmail(req.body.code);
    if (!result) {
        res.status(400).send({errorsMessages: [{ message: 'пользователь уже подтвержден', field: "code" }]});
        return
    }
    res.sendStatus(204)
    return
});

authRouter.post('/registration-email-resending', emailResendingValidation(),  async (req: Request, res: Response) => {
    const email = req.body.email;
    await UsersService.resendConfirmationEmail(email);
        res.sendStatus(204)
});

