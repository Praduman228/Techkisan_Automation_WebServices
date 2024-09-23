const mongoose = require('mongoose')

const attendanceSchema = new mongoose.Schema({
	date: { type: Date, required: true },
	status: { type: String, enum: ['P', 'A','H','SL','CL'], required: true },
  });

const managerSchema=mongoose.Schema({
	firstName: String,
	middleName: String,
	lastName: String,
	username:String,
	password:String,
	managerId: String,
	email: String,
	managerType: String,
	managerStatus: String,
	endDate: Date,
	dateOfHire: Date,
	department: String,
	jobTitle: String,
	location: String,
	reportingTo: String,
	source: String,
	payRate: String,
	bloodGroup: String,
	spouseName: String,
	fatherName: String,
	motherName: String,
	mobile: String,
	phone: String,
	otherEmail: String,
	dob: Date,
	nationality: String,
	gender: String,
	maritalStatus: String,
	drivingLicence: String,
	address1: String,
	address2: String,
	city: String,
	country: String,
	state: String,
	postalCode: String,
	biography: String,
	welcomeEmail: Boolean,
	loginDetails: Boolean,
	Image: [{
		type:mongoose.Types.ObjectId,
		ref: 'empimg',
		required: false,
	},] ,
	employee:[{
        type: mongoose.Types.ObjectId,
        ref: 'Employee',
        required: false,
    }],

    punchRecords: [{
        date: Date,
        punchInTime: Date,
        punchOutTime: Date,
        workDuration: Number, 
		status: String,
    }],
	leaves:[{
		type: mongoose.Types.ObjectId,
        ref: 'Leave',
        required: false,
	}],
	attendance:[attendanceSchema]
})

module.exports = mongoose.model('Manager', managerSchema)