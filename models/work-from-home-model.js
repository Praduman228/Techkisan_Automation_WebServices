const mongoose = require('mongoose');

const workFromHomeSchema =mongoose.Schema({
    employeeId: {
        type: mongoose.Schema.ObjectId,
        ref: "Employee",
        required: true,
    },
    startDate: {
        type: Date,
    },
    endDate: {
        type: Date,
    },
    inTime:String,
    outTime:String,
    dayType:String,
    
    remark:String
   
})

module.exports = mongoose.model('WorkFromHome', workFromHomeSchema);