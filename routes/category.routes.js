const express = require('express')
const { authenticate } = require('../middleware/auth.middleware')
const slugify = require('slugify');
const { categoryModel } = require('../model/category.model');

const categoryRoute = express.Router()



categoryRoute.get('/get/:_id', async (req, res) => {
    try {
        let _id = req.params._id
        let categorie = await categoryModel.find({ _id })
        res.send({ "msg": "Category data fetch successfully", "success": true, categorie })
    } catch (err) {
        console.log(err);
        res.send({ "msg": "Not found categories", "success": false, err })
    }
})

categoryRoute.use(authenticate)

categoryRoute.get('/get', async (req, res) => {
    try {
        let query = {};
        let owner = req.userID
        query.owner = owner;

        if (req.query.name) {
            query.name = req.query.name
        }

        let categories = await categoryModel.find(query)
        res.send({ "msg": "Categories list fetch successfully", "success": true, categories })
    } catch (err) {
        console.log(err);
        res.send({ "msg": "Not found categories", "success": false, err })
    }
})

categoryRoute.post('/create', async (req, res) => {
    try {

        const { name, image } = req.body
        const slug = slugify(req.body.name, { lower: true, strict: true });
        let userId = req.userID

        const category = new categoryModel({ name, slug, image, owner: userId })
        await category.save()

        res.send({ "msg": "New category has been created", "success": true })
    } catch (err) {
        res.send({ "msg": "Category not created", "success": false, err })
    }
})

categoryRoute.patch('/edit/:_id', async (req, res) => {
    try {
        let _id = req.params._id
        let payload = req.body
        await categoryModel.findByIdAndUpdate({ _id }, payload)
        res.send({ "msg": "Category has been updated successfully", "success": true })

    } catch (err) {
        console.log(err);
        res.send({ "msg": "Category not updated", "success": false, err })
    }
})

categoryRoute.delete('/delete/:_id', async (req, res) => {
    try {

        let _id = req.params._id
        await categoryModel.findByIdAndDelete({ _id })

        res.send({ "msg": "Category has been deleted", "success": true })
    } catch (err) {
        console.log(err);
        res.send({ "msg": "Category not deleted", "success": false, err })
    }
})



module.exports = {
    categoryRoute
}