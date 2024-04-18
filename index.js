const express = require('express')
const connection = require('./config/db')
const { userRoute } = require('./routes/user.routes')
var cors = require('cors')
const { categoryRoute } = require('./routes/category.routes')
const { productRoute } = require('./routes/product.routes')
require('dotenv').config()

const app = express()
app.use(express.json())
app.use(cors())

app.get('/', (req, res) => {
    res.send("Welcome to  Database Arba DB")
})

app.use('/users', userRoute)
app.use('/category', categoryRoute)
app.use('/product', productRoute)

app.listen(process.env.port, async () => {
    try {
        await connection
        console.log('Connected to db')
    } catch {
        console.log('Not connected to db')
    }
    console.log(`Server running at ${process.env.port}`)
})