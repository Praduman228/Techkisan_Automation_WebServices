const express =require('express');

const app = express();
const cors = require('cors');
const path=require('path');
const cookieParser=require('cookie-parser');
const expressSession = require('express-session');
const db=require('./configs/mongoose-connection')
const indexRoute=require("./routes/indexRoute")
const employeesRoute=require("./routes/employeeRoute")
const adminRoute=require("./routes/adminRoutes")
require('dotenv').config()
app.use(cookieParser())
app.use(cors({
  origin: ['https://techkisan-automation-web.vercel.app'], 
  methods: ['POST,GET'],
  credentials: true,               
}));
app.use(express.json());
app.use(express.urlencoded({ extended:false }));
app.use(expressSession({
  resave: false,
  saveUninitialized: false,
  secret: process.env.SESSION_SECRET,

}))
app.use(express.static(path.join(__dirname,"public")));

app.use("/",indexRoute);
app.use("/employees",employeesRoute);
app.use("/admin",adminRoute);


app.listen(8000);