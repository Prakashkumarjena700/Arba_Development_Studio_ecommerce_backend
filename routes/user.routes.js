const express = require("express")
const { userModel } = require("../model/user.model")
const jwt = require("jsonwebtoken")
const bcrypt = require('bcrypt');
const { authenticate } = require("../middleware/auth.middleware");
var nodemailer = require('nodemailer');

const userRoute = express.Router()

userRoute.post("/register", async (req, res) => {
    const { fullName, userName, email, password, avatar } = req.body

    if (fullName == null || userName == null || email == null || password == null) {
        res.send({ "msg": "Please all the required fields", "success": false })
    } else {
        try {
            const user = await userModel.find({ email })
            if (user.length > 0) {
                res.send({ "msg": "Already have an account please login", "success": false })
            } else {
                bcrypt.hash(password, 9, async (err, hash) => {
                    if (err) {
                        res.send("Something went wrong")
                    } else {
                        const user = new userModel({ fullName, userName, email, password: hash, avatar })
                        await user.save()
                        res.send({ "msg": "New user has been register", "success": true })
                    }
                });
            }

        } catch (err) {
            console.log(err)
            res.send({ "msg": "Can't register", "success": false, err })
        }
    }
})

userRoute.post("/login", async (req, res) => {
    const { userName, password } = req.body
    if (userName == null || password == null) {
        res.send({ "msg": "Please all the required fields", "success": false })
    } else {
        try {
            const user = await userModel.find({ userName })
            if (user.length > 0) {
                bcrypt.compare(password, user[0].password, (err, result) => {
                    if (result) {
                        const token = jwt.sign({ userID: user[0]._id }, "arbadevelopmentstudio")
                        res.send({
                            "msg": "Login sucessful",
                            "success": true,
                            token,
                            user: user[0]
                        })
                    } else {
                        res.send({ "msg": "Wrong crediential", "success": false })
                    }
                });
            } else {
                res.send({ "msg": "Wrong crediential", "success": false })
            }
        } catch (err) {
            res.send({ "msg": "Something Wrong", "success": false, err })
        }
    }
})

userRoute.get('/reset-password/:id/:token', async (req, res) => {
    const { id, token } = req.params
    const user = await userModel.findOne({ _id: id })
    if (!user) {
        return res.send({ 'msg': 'User not existing', success: false })
    }
    const secreate = 'arbaTokenSecreate123' + user.password;
    try {
        const verify = jwt.verify(token, secreate)

        res.render("index", { id: user._id })
    } catch (err) {
        console.log(err);
        return res.send(err)
    }
})

userRoute.post("/forgot-password", async (req, res) => {
    const { email } = req.body;
    try {
        const user = await userModel.findOne({ email });
        if (!user) {
            res.send({ 'msg': 'User not existing', success: false })
        } else {
            const secreate = 'arbaTokenSecreate123' + user.password;
            const token = jwt.sign({ email: user.email, id: user._id }, secreate, { expiresIn: '10m' })
            const link = `https://outrageous-lapel-bat.cyclic.app/users/reset-password/${user._id}/${token}`;

            var transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: 'prakashkumarjena700@gmail.com',
                    pass: 'ycze uofx ftxy eavq'
                }
            });
            var mailOptions = {
                from: 'prakashkumarjena700@gmail.com',
                to: email,
                subject: 'Reset Password for shopeZ',
                html: `
                    <h3><span style="color: #00AACF;">ShopeZ</span></h3>
                    <p>Hello,</p>
                    <p>You have requested to reset your password for shopeZ. Please click the link below to reset your password:</p>
                    <a href="${link}">Reset Password</a>
                    <p>This link will expire in 10 minutes.</p>
                    <p>If you didn't request this, you can safely ignore this email.</p>
                    <p>Best regards,<br/>shopeZ Team</p>
                    `
            };

            transporter.sendMail(mailOptions, function (error, info) {
                if (error) {
                    return res.send(error);
                } else {
                    return res.send({ 'msg': 'Mail has been sent', 'success': true, 'data': info.response });
                }
            });
        }

    } catch (err) {
        console.log(err);
        res.send({ 'msg': 'mail has not sent', success: false, 'error': err })
    }
})


userRoute.patch("/edit/:_id", async (req, res) => {
    try {
        let _id = req.params._id;
        let payload = req.body;

        if (payload.password) {
            const hashedPassword = await bcrypt.hash(payload.password, 9);
            payload.password = hashedPassword;
        }

        const updatedUser = await userModel.findByIdAndUpdate({ _id }, payload, { new: true });

        res.send({ "msg": "User data has been updated successfully", "success": true, "data": updatedUser })

    } catch (err) {
        res.send({ "msg": "User has not been updated", "success": false, err })
        console.log(err)
    }

})

userRoute.delete("/delete/:_id", async (req, res) => {
    try {
        let _id = req.params._id;
        await userModel.findByIdAndDelete({ _id })
        res.send({ "msg": "User data has been deleted successfully", "success": true })

    } catch (err) {
        res.send({ "msg": "User has not been deleted", "success": false, err })
        console.log(err)
    }
})





module.exports = {
    userRoute
}