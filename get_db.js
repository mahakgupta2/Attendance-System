const fs = require('fs');
const mongoose = require('mongoose');
mongoose.connect('mongodb+srv://mahakgupta956_db_user:unX3sSLQfweN4Wqv@complete-backend.qwqxuzi.mongodb.net/attendance')
  .then(async () => {
    const Student = mongoose.model('Student', new mongoose.Schema({}, {strict: false}), 'students');
    const bcrypt = require('bcryptjs');
    const pwd = await bcrypt.hash('123456', 10);
    const result = await Student.findOneAndUpdate({ studentId: '8279421516' }, { $set: { password: pwd } });
    console.log("Updated password for Mahak to 123456");
    process.exit();
  });
