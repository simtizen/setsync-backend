const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");
const crypto = require("crypto");
require('dotenv').config();
const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/SetSync"

const app = express();

app.use(express.json());
app.use(cors());

// Mongoose connection
async function main() {
  await mongoose.connect(MONGODB_URI);
  console.log("Connected to MongoDB");
}
main().catch((err) => console.error("Database connection error:", err));

// Schemas & Models
const userSchema = new mongoose.Schema({
  usrname: { type: String, required: true, unique: true },
  password: { type: String, required: true, select: false },
  role: { type: String, enum: ['admin', 'member'], default: 'member' },
  group: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Group",
    default: null
  },
  token: { type: String, default: null }
});

const setlistSchema = new mongoose.Schema({
  title: { type: String, required: true },
  eventDate: { type: Date, required: true },
  group: { type: mongoose.Schema.Types.ObjectId, ref: "Group", required: true },
  author: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  lead: String,
  bgvs: String,
  songs: [{
    title: String,
    key: String,
    bpm: Number,
    notes: String,
    lead: String,
    bgvs: String
  }],
}, { timestamps: true });

const groupSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  inviteCode: {
    type: String,
    required: true,
    unique: true,
    default: () => crypto.randomBytes(4).toString("hex") // Automatically generates an 8-character secure code
  }
}, { timestamps: true });

const User = mongoose.model("User", userSchema);
const setList = mongoose.model("SetList", setlistSchema);
const Group = mongoose.model("Group", groupSchema);

//middleWare to check Admin
const requireAdmin = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || authHeader.trim() === "" || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized:Invalid or expired Session" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const user = await User.findOne({ token: token });

    if (!user || user.role !== 'admin') {
      console.log(user, user.role)
      return res.status(403).json({ error: "Access denied: Admins only." });
    }

    req.user = user;
    next();

  } catch (err) {
    console.error({ "Admin Error": err });
    return res.status(500).json({ error: "Server error verifying admin status" });
  }
};

//middleWare to authenticate a user
const authenticateUser = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || authHeader.trim() === "" || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized: No token provided." });
  }

  const token = authHeader.split(" ")[1];

  try {
    const user = await User.findOne({ token: token });

    if (!user) {
      return res.status(401).json({ error: "Invalid or expired Session" });
    }

    req.user = user;
    next();

  } catch (err) {
    console.error(err)
    return res.status(401).json({ error: "Unauthorized: Invalid or expired session." });
  }
}

// Routes
app.get("/", async (req, res) => {
  res.send("working");
});

//user
app.post("/register", async (req, res) => {
  const { usrname, password } = req.body;

  if (!usrname || !password || usrname.trim() === "" || password.trim() === "") {
    return res.status(400).json({ error: "Username and password are required" });
  }

  try {
    const existingUser = await User.findOne({ usrname: usrname.trim() });
    if (existingUser) {
      return res.status(400).json({ msg: "Username already taken" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      usrname: usrname.trim(),
      password: hashedPassword,
    });

    await newUser.save();

    res.status(201).json({
      msg: "User registered successfully",
      userId: newUser._id,
      usrname: newUser.usrname,
    });
  } catch (err) {
    console.error("Registration error:", err);
    res.status(500).json({ error: "Server error during registration" });
  }
});

app.post("/login", async (req, res) => {
  let { usrname, password } = req.body;

  if (!usrname || !password || usrname.trim() === "" || password.trim() === "") {
    return res.status(400).json({ error: "Input Your Credentials" });
  }

  try {
    usrname = usrname.trim();
    password = password.trim();

    const user = await User.findOne({ usrname }).select("+password");
    if (!user) {
      return res.status(400).json({ error: "Invalid username or password" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ error: "Invalid username or password" });
    }

    const loginToken = crypto.randomBytes(64).toString("hex");

    user.token = loginToken;
    await user.save();

    const userResponse = user.toObject();
    delete userResponse.password;
    delete userResponse.__v;
    delete userResponse.token;

    return res.json({
      msg: "Loggedin in successfully",
      token: loginToken,
      user: userResponse
    });

  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ error: "Error signing in" });
  }
});

app.post("/logout", authenticateUser, async (req, res) => {
  try {
    // req.user is ALREADY the database document attached by authenticateUser!
    req.user.token = null;
    await req.user.save();

    return res.json({ msg: "Logged out successfully" });
  } catch (err) {
    console.error({ "Logout Error": err });
    return res.status(500).json({ error: "Error logging out" });
  }
});

app.post("/change-username", authenticateUser, async (req, res) => {
  const newUsrName = req.body.newUsrname;

  if (!newUsrName || newUsrName.trim() === "") {
    return res.status(400).json({ error: "New username required" });
  }

  if (newUsrName.trim() === req.user.usrname) {
    return res.status(400).json({ error: "Change your username" });
  }

  try {
    const existingUser = await User.findOne({ usrname: newUsrName.trim() });

    if (existingUser) {
      return res.status(400).json({ error: "Username is already in use" });
    }

    req.user.usrname = newUsrName.trim();
    await req.user.save();

    return res.json({ msg: "Sucessfully Changed your username" });

  } catch (err) {
    console.error({ "Cange Username Error": err });
    return res.status(500).json({ error: "Error Chnaging username" });
  }
});

app.post("/change-password", authenticateUser, async (req, res) => {
  const { password, newPassword } = req.body;

  if (!password || password.trim() === "") {
    return res.status(400).json({ error: "Old password required" });
  }

  if (!newPassword || newPassword.trim() === "") {
    return res.status(400).json({ error: "New password required" });
  }

  if (password === newPassword) {
    return res.status(400).json({ error: "Both Passwords are the same" });
  }

  try {
    const userWithAuth = await User.findById(req.user._id).select("+password");

    const isPasswordValid = await bcrypt.compare(password.trim(), userWithAuth.password);

    if (!isPasswordValid) {
      return res.status(400).json({ error: "Incorrect Old Password" });
    }
    const hashNewPassword = await bcrypt.hash(newPassword.trim(), 10);

    userWithAuth.password = hashNewPassword;
    await userWithAuth.save();

    return res.json({ msg: "Successfully changed your password" });

  } catch (err) {
    console.error({ "Change Password Error": err });
    return res.status(500).json({ error: "Error changing password" });
  }
});

//groups
app.post("/create-group", authenticateUser, async (req, res) => {
  if (req.user.group && req.user.role === "admin") {
    return res.status(403).json({ error: "Make Someone else admin first" })
  }

  const { name } = req.body;

  if (!name || name.trim() === "") {
    return res.status(400).json({ error: "Input a name" })
  }

  try {
    const newGroup = new Group({
      name: name.trim()
    });
    await newGroup.save();

    req.user.group = newGroup._id;
    req.user.role = "admin"
    await req.user.save();

    return res.status(201).json({
      msg: "Group created successfully",
      groupName: newGroup.name,
      inviteCode: newGroup.inviteCode
    });

  } catch (err) {
    console.error("Error creating group:", err);
    return res.status(500).json({ error: "Failed to create group" });
  }
});

app.post("/join-group", authenticateUser, async (req, res) => {
  const { inviteCode } = req.body;

  if (!inviteCode || inviteCode.trim() === "") {
    return res.status(400).json({ error: "Invite code not provided" });
  }

  try {
    const group = await Group.findOne({ inviteCode: inviteCode.trim() });

    if (!group) {
      return res.status(404).json({ error: "Group not found" });
    }

    let user = await User.findById(req.user._id);

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    user.group = group._id;
    user.role = 'member';

    await user.save();

    return res.json({
      msg: "Successfully joined group",
      group_name: group.name,
      groupId: group._id
    });

  } catch (err) {
    console.error({ "Join Error": err })
    return res.status(500).json({ error: "An error occurred while joining the group" });
  }
});

app.post("/leave-group", authenticateUser, async (req, res) => {
  const user = req.user;

  if (!user.group) {
    return res.status(400).json({ error: "You don't belong to a group" });
  }

  try {
    if (user.role === "admin") {
      const otherAdminExists = await User.findOne({
        group: req.user.group,
        role: "admin",
        _id: { $ne: req.user._id }
      });

      if (!otherAdminExists) {
        return res.status(400).json({ error: "You are currently admin. make someone else admin" });
      }
    }

    user.group = null;
    user.role = "member";

    await user.save();

    return res.json({ msg: "Successfully left the group" });

  } catch (err) {
    console.error({ "Leave Error": err });
    return res.status(500).json({ error: "An error occured while leaving the group." });
  }
});

//setlists
app.get("/setlists", authenticateUser, async (req, res) => {
  if (!req.user.group) {
    return res.status(400).json({ error: "You must join a group first" });
  }

  try {
    const currentDate = new Date();

    const upcoming = await setList.find({
      group: req.user.group,
      eventDate: { $gte: currentDate }
    }).sort({ eventDate: 1 });

    const past = await setList.find({
      group: req.user.group,
      eventDate: { $lt: currentDate }
    }).sort({ eventDate: -1 });

    return res.status(200).json({
      upcoming: upcoming,
      past: past
    });

  } catch (err) {
    console.error({ "setlist error": err });
    return res.status(500).json({ error: "Error fetching setlists" });
  }
});

//profile
app.get("/profile", authenticateUser, async (req, res) => {
  try {
    const user = req.user;

    // Default states for a new user
    let groupName = "No Group Assigned";
    let groupId = user.group || null;
    let belongsToGroup = false;

    // Only look up the group IF the user actually has one
    if (user.group) {
      const group = await Group.findById(user.group);

      if (group) {
        belongsToGroup = true;
        groupName = group.name;
      } else {
        // Failsafe: User has a group ID, but the group was deleted from the database
        groupId = null;
      }
    }

    return res.json({
      groupName: groupName,
      groupId: groupId,
      belongsToGroup: belongsToGroup,
      userId: user._id,
      usrname: user.usrname,
      role: user.role
    });

  } catch (err) {
    console.error({ "Profile Error": err });
    return res.status(500).json({ error: "Error getting profile" });
  }
});

//members
app.get("/group/members", authenticateUser, async (req, res) => {
  if (!req.user.group) {
    return res.status(400).json({ error: "You must join a group first" });
  }

  try {
    const members = await User.find({ group: req.user.group }).select("_id usrname role");

    if (!members) {
      return res.status(400).json({ error: "No members in your group" });
    }

    return res.status(200).json(members);
  } catch (err) {
    console.error({ "Fetch Members Error": err });
    return res.status(500).json({ error: "Failed to fetch group members" });
  }
});

//Admin priviledge
//setlists
app.post("/admin/setlists", requireAdmin, async (req, res) => {
  const { title, eventDate, songs, lead, bgvs } = req.body;

  if (!req.user.group) {
    return res.status(400).json({ error: "Admin must belong to a group" });
  }

  if (!title || title.trim() === "") {
    return res.status(400).json({ error: "Setlist title is required" });
  }

  if (!eventDate) {
    return res.status(400).json({ error: "Event date is required" });
  }

  if (!Array.isArray(songs)) {
    return res.status(400).json({ error: "Songs must be formatted as an array" });
  }

  try {
    const newSetlist = new setList({
      title: title.trim(),
      eventDate: new Date(eventDate),
      songs: songs,
      author: req.user._id,
      group: req.user.group,
      lead: lead,
      bgvs: bgvs
    });

    await newSetlist.save();

    return res.status(201).json({
      msg: "Setlist created successfully",
      setlist: newSetlist
    });

  } catch (err) {
    console.error("Error creating setlist:", err);
    return res.status(500).json({ error: "Failed to create setlist" });
  }
});

app.delete("/admin/setlists/:id", requireAdmin, async (req, res) => {
  const setlistId = req.params.id;

  try {
    const setlist = await setList.findById(setlistId);

    if (!setlist) {
      return res.status(404).json({ error: "Setlist not found" });
    }

    if (setlist.group.toString() !== req.user.group.toString()) {
      return res.status(403).json({ error: "You cannot delete a setlist from another group" });
    }

    await setList.findByIdAndDelete(setlistId);

    return res.status(200).json({ msg: "Setlist successfully deleted" });

  } catch (err) {
    console.error({ "Delete Error [S]": err });
    return res.status(500).json({ error: "There was an error deleting the setlist" });
  }
});

app.put("/admin/setlists/:id", requireAdmin, async (req, res) => {
  const setlistId = req.params.id;
  const { title, eventDate, songs, lead, bgvs} = req.body;

  try {
    if (!setlistId) {
      return res.status(400).json({ error: "Setlist Id required" });
    }

    const foundSetlist = await setList.findById(setlistId);

    if (!foundSetlist) {
      return res.status(400).json({ error: "Setlist not found" });
    }

    if (!foundSetlist.group || foundSetlist.group.toString() !== req.user.group.toString()) {
      return res.status(400).json({ error: "This Setlist does not belong to your group" });
    }

    if (title) foundSetlist.title = title.trim();
    if (eventDate) foundSetlist.eventDate = eventDate;
    if (songs) foundSetlist.songs = songs;
    if (lead) foundSetlist.lead = lead;
    if (bgvs) foundSetlist.bgvs = bgvs;

    await foundSetlist.save();

    return res.json({
      msg: "Setlist Updated Sucessfully",
      foundSetlist
    });

  } catch (err) {
    console.error({ "Update Error": err });
    return res.status(500).json({ error: "There was an error updating the setlist" });
  }
});

//groups
app.get("/admin/groups/get-invite-code/:groupId", requireAdmin, async (req, res) => {
  const { groupId } = req.params;

  if (!groupId || groupId.trim() === "") {
    return res.status(400).json({ error: "Input the group id" });
  }

  try {
    const group = await Group.findById(groupId.trim());

    if (!group) {
      return res.status(400).json({ error: "group not found" });
    }

    const groupInviteCode = group.inviteCode

    return res.json({ inviteCode: group.inviteCode });

  } catch (err) {
    console.error({ "Get Code": err })
    return res.status(500).json({ error: "error getting invite code" })
  }
});

//member
app.post("/admin/groups/make-admin", requireAdmin, async (req, res) => {
  const { memberId } = req.body;

  if (!memberId) {
    return res.status(400).json({ error: "Member ID is required" });
  }

  try {
    //check user
    const member = await User.findById(memberId);

    if (!member) {
      return res.status(400).json({ error: "User not found" });
    }

    if (!member.group || !req.user.group || member.group.toString() !== req.user.group.toString()) {
      return res.status(403).json({ error: "You do not belong to the same group" });
    }

    //check for group
    if (member.role === "admin") {
      return res.status(400).json({ error: `${member.usrname} is already an admin` });
    }

    member.role = "admin";
    await member.save();

    return res.json({ msg: `Successfully made ${member.usrname} an admin` });

  } catch (error) {
    console.error({ "make Admin Error": error });
    return res.status(500).json({ error: "Error making member admin" });
  }
});

app.delete("/admin/groups/remove-member", requireAdmin, async (req, res) => {
  const { memberId } = req.body;

  if (!memberId || memberId.trim() === "") {
    return res.status(400).json({ error: "Member ID is required" });
  }

  //check memberId !== req.user._id
  if(memberId.trim() === req.user._id.toString()) {
    return res.status(400).json({error : "You can't remove yourself from a group. Go to /leave-group"});
  }
  
  try {
    const memberExists = await User.findById(memberId.trim());

    if(!memberExists) {
      return res.status(400).json({error : "This user doesn't exist"});
    }

    if (!memberExists.group || memberExists.group.toString() !== req.user.group.toString()) {
      return res.status(400).json({error : "You don't belong to the same group"});
    }

    memberExists.group = null;
    memberExists.role = 'member';

    await memberExists.save();

    return res.json({msg: 'Sucessfully removed user from group'});
  } catch (err) {
    console.error({ "Remove Member Error": err });
    return res.status(500).json({ error: "Error removing member from group" });
  }
});

//Change member password
app.post("/admin/groups/reset-password", requireAdmin, async (req, res) => {
  const { memberId, newPassword } = req.body;

  if (!memberId || !newPassword || newPassword.trim() === "") {
    return res.status(400).json({ error: "Member ID and new password are required" });
  }

  try {
    const member = await User.findById(memberId);
    if (!member) {
      return res.status(404).json({ error: "User not found" });
    }

    // Ensure the member belongs to the admin's group
    if (!member.group || !req.user.group || member.group.toString() !== req.user.group.toString()) {
      return res.status(403).json({ error: "You can only reset passwords for members of your own group" });
    }

    // Hash the new temporary password
    const hashedPassword = await bcrypt.hash(newPassword.trim(), 10);

    // Update password and force-logout the user by clearing their token
    member.password = hashedPassword;
    member.token = null;
    await member.save();

    return res.json({ msg: `Successfully reset password for ${member.usrname}` });

  } catch (err) {
    console.error({ "Admin Reset Error": err });
    return res.status(500).json({ error: "Failed to reset password" });
  }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));