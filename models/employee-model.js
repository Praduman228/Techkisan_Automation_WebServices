const mongoose = require('mongoose')


const employeeSchema=mongoose.Schema({
	firstName: String,
	middleName: String,
	lastName: String,
	username:String,
	password:String,
	employeeId: String,
	email: String,
	employeeType: String,
	employeeStatus: String,
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
	Image: Buffer, 
	  
	ImageType:String
})

module.exports = mongoose.model('Employee', employeeSchema)