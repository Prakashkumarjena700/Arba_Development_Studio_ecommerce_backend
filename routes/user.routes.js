const express = require("express")
const { userModel } = require("../model/user.model")
const jwt = require("jsonwebtoken")
const bcrypt = require('bcrypt');
const { authenticate } = require("../middleware/auth.middleware");

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

userRoute.use(authenticate)

userRoute.patch("/edit/:_id", async (req, res) => {
    try {
        let _id = req.params._id;
        let payload = req.body;

        if (payload.password) {
            const hashedPassword = await bcrypt.hash(payload.password, 9);
            payload.password = hashedPassword;
        }

        await userModel.findByIdAndUpdate({ _id }, payload)
        res.send({ "msg": "User data has been updated successfully", "success": true })

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