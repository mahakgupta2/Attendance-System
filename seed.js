const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const defaultSubjects = [
  { name: "Data Structures & Algorithms", code: "CS201", startTime: "09:00", endTime: "10:30" },
  { name: "Object Oriented Programming", code: "CS202", startTime: "10:30", endTime: "12:00" },
  { name: "Database Management Systems", code: "CS203", startTime: "13:00", endTime: "14:30" },
  { name: "Computer Networks", code: "CS204", startTime: "14:30", endTime: "16:00" }
];

const studentNames = [
  "Aarav Sharma", "Vivaan Gupta", "Aditya Singh", "Vihaan Patel",
  "Ananya Reddy", "Diya Verma", "Isha Kumar", "Neha Joshi"
];

const generateDescriptor = () => Array.from({ length: 128 }, () => Math.random() * 0.1);

async function seedDatabase() {
  try {
    // 1. Connect first
    await mongoose.connect("mongodb+srv://mahakgupta956_db_user:unX3sSLQfweN4Wqv@complete-backend.qwqxuzi.mongodb.net/attendance");
    console.log("Cloud MongoDB Atlas Connected ✅");

    // 2. Define Models
    const Subject = mongoose.model("Subject", new mongoose.Schema({
      name: { type: String, required: true },
      code: { type: String, required: true },
      teacherUsername: { type: String, default: "" },
      startTime: { type: String, default: "" },
      endTime: { type: String, default: "" },
      createdAt: { type: Date, default: Date.now }
    }));

    const Attendance = mongoose.model("Attendance", new mongoose.Schema({
      studentId: String,
      class: String,
      subject: String,
      subjectName: String,
      date: String,
      time: String,
      status: { type: String, enum: ["present", "absent"], default: "present" },
      image: String
    }));

    const Student = mongoose.model("Student", new mongoose.Schema({
      studentId: String,
      name: { type: String, default: "" },
      password: { type: String, default: "" },
      parentPhone: { type: String, default: "" },
      image: String,
      descriptor: [Number],
      createdAt: { type: Date, default: Date.now }
    }));

    console.log("🧹 Clearing old dummy data...");
    await Attendance.deleteMany({});
    console.log("Deleted old attendance records.");
    
    // We will leave students and subjects as they are, just add more if needed
    console.log("📚 Checking/Adding Subjects...");
    for (let sub of defaultSubjects) {
      if (!(await Subject.findOne({ code: sub.code }))) {
        await new Subject(sub).save();
      }
    }
    const subjects = await Subject.find();
    console.log(`Loaded ${subjects.length} subjects.`);

    console.log("🎓 Seeding Students...");
    const hashedPassword = await bcrypt.hash("password123", 10);
    const students = [];
    
    const myId = "2315001289";
    if (!(await Student.findOne({ studentId: myId }))) {
      const me = new Student({
        studentId: myId,
        name: "Test User",
        password: hashedPassword,
        parentPhone: "9876543210",
        descriptor: generateDescriptor(),
        image: "dummy.jpg"
      });
      await me.save();
    }
    students.push(await Student.findOne({ studentId: myId }));

    for (let i = 0; i < studentNames.length; i++) {
        const sid = "231500" + (1000 + i);
        if (!(await Student.findOne({ studentId: sid }))) {
            const s = new Student({
            studentId: sid,
            name: studentNames[i],
            password: hashedPassword,
            parentPhone: "987654321" + i,
            descriptor: generateDescriptor(),
            image: "dummy.jpg"
            });
            await s.save();
        }
        if(sid !== myId) students.push(await Student.findOne({ studentId: sid }));
    }
    console.log(`Loaded ${students.length} students.`);

    console.log("📅 Generating 30 days of Attendance History...");
    const today = new Date();
    let totalRecords = 0;

    for (let i = 30; i >= 0; i--) {
      const d = new Date();
      d.setDate(today.getDate() - i);
      
      if (d.getDay() === 0) continue; // Skip Sunday

      const dateString = d.toISOString().split('T')[0];
      
      for (const subject of subjects) {
        for (const student of students) {
          const isPresent = Math.random() < 0.85;
          const status = isPresent ? "present" : "absent";
          
          await new Attendance({
            studentId: student.studentId,
            class: "BTECH",
            subject: subject.code,
            subjectName: subject.name,
            date: dateString,
            time: subject.startTime,
            status: status,
            image: "dummy.jpg"
          }).save();
          totalRecords++;
        }
      }
    }

    console.log(`✅ Success! Created ${totalRecords} attendance records.`);
    console.log("🚀 Your database is now very STRONG and full of data.");
    
    // Close the connection explicitly
    await mongoose.connection.close();
    process.exit(0);
  } catch (err) {
    console.error("❌ Error while seeding:", err);
    await mongoose.connection.close();
    process.exit(1);
  }
}

seedDatabase();
