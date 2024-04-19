const mongoose = require('mongoose')

const productSchema = mongoose.Schema({
    title: { type: String, require: true },
    description: { type: String, require: true },
    slug: { type: String, require: true },
    price: { type: Number, require: true },
    category: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Category',
        required: true,
    },
    image: { type: String, require: true },
    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    }
}, {
    versionKey: false
})

const productModel = mongoose.model("Product", productSchema)

module.exports = {
    productModel
}