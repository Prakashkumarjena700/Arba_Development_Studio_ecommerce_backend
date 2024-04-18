const mongoose = require('mongoose')

const categorySchema = mongoose.Schema({
    name: { type: String, require: true },
    slug: { type: String, require: true },
    image: { type: String, require: true },
    owner: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
    }
}, {
    versionKey: false
})

const categoryModel = mongoose.model("Category", categorySchema)

module.exports = {
    categoryModel
}