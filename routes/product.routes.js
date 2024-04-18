const express = require('express')
const { authenticate } = require('../middleware/auth.middleware')
const { productModel } = require('../model/product.modal')

const productRoute = express.Router()



productRoute.get('/get/:_id', async (req, res) => {
    try {
        let _id = req.params._id
        let product = await productModel.find({ _id })
        res.send({ "msg": "Product data fetch successfully", "success": true, product })
    } catch (err) {
        console.log(err);
        res.send({ "msg": "Not found product", "success": false, err })
    }
})


productRoute.use(authenticate)

productRoute.get('/get', async (req, res) => {
    try {
        let query = {};

        let owner = req.userID
        query.owner = owner;

        if (req.query.title) {
            query.title = { $regex: new RegExp(req.query.title, 'i') };
        }

        if (req.query.category) {
            query.category = req.query.category;
        }

        let sortOptions = {};

        if (req.query.sort) {
            const sortField = req.query.sort.toLowerCase();
            sortOptions[sortField] = Number(req.query.order);
        }

        let products = await productModel.find(query).sort(sortOptions);

        res.send({ "msg": "Product list fetch successfully", "success": true, products });
    } catch (err) {
        console.log(err);
        res.send({ "msg": "Error fetching products", "success": false, err });
    }
});

productRoute.post("/create", async (req, res) => {
    try {
        const { title, description, price, category, image } = req.body
        let userId = req.userID

        const product = new productModel({ title, description, price, category, image, owner: userId })
        await product.save()
        res.send({ "msg": "Product has been created successfully", "success": true })

    } catch (err) {
        console.log(err);
        res.send({ "msg": "Product has not been created", "success": false, err })
    }
})

productRoute.patch('/edit/:_id', async (req, res) => {
    try {
        let _id = req.params._id
        let payload = req.body
        await productModel.findByIdAndUpdate({ _id }, payload)
        res.send({ "msg": "Product data has been updated successfully", "success": true })

    } catch (err) {
        console.log(err);
        res.send({ "msg": "Product data not updated", "success": false, err })
    }
})

productRoute.delete('/delete', async (req, res) => {
    try {

        const productIds = req.body.productIds;

        if (!Array.isArray(productIds)) {
            return res.status(400).send({ "msg": "Invalid request, productIds must be an array", "success": false });
        }
        await productModel.deleteMany({ _id: { $in: productIds } });

        res.send({ "msg": "Product has been deleted", "success": true })
    } catch (err) {
        console.log(err);
        res.send({ "msg": "Product has not deleted", "success": false, err })
    }
})



module.exports = {
    productRoute
}