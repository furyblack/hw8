import express, { Request, Response } from 'express'
import cookieParser from 'cookie-parser'

export const app = express()
app.use(cookieParser())

// app.post('/auth/example', (req: Request, res: Response) => {
//     res.cookie('cookie_name', value, {httpOnly: true,secure: true})
//     res.status(204).send('Hello samurai from it-incubator!!!')
// })
// app.get('/auth/result', async (req: Request, res: Response) => {
//     const cookie_name= req.cookies.cookie_name
//     res.sendStatus(CodeResponsesEnum.Not_content_204)
// })