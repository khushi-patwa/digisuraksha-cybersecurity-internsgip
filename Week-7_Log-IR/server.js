require("dotenv").config();

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();

app.use(cors());
app.use(express.json());

/* -----------------------------
   Fake Database
----------------------------- */

const users = [];

/* -----------------------------
   Register
----------------------------- */

app.post("/register", async (req, res) => {

const { name, email, password, age, gender } = req.body;

if (!email || !password) {
return res.status(400).json({ message: "Email and password required" });
}

const existingUser = users.find(u => u.email === email);

if (existingUser) {
return res.status(400).json({ message: "User already exists" });
}

const hashedPassword = await bcrypt.hash(password, 10);

users.push({
name,
email,
password: hashedPassword,
age,
gender
});

res.json({ message: "User registered successfully" });

});

/* -----------------------------
   Login
----------------------------- */

app.post("/login", async (req, res) => {

const { email, password } = req.body;

const user = users.find(u => u.email === email);

if (!user) {
return res.status(401).json({ message: "Invalid email or password" });
}

const validPassword = await bcrypt.compare(password, user.password);

if (!validPassword) {
return res.status(401).json({ message: "Invalid email or password" });
}

const token = jwt.sign(
{ email: user.email },
process.env.JWT_SECRET,
{ expiresIn: "1h" }
);

res.json({ token });

});

/* -----------------------------
   Auth Middleware
----------------------------- */

function authenticateToken(req, res, next) {

const authHeader = req.headers["authorization"];
const token = authHeader && authHeader.split(" ")[1];

if (!token) return res.sendStatus(401);

jwt.verify(token, process.env.JWT_SECRET, (err, user) => {

if (err) return res.sendStatus(403);

req.user = user;

next();

});

}

/* -----------------------------
   Healthcare Logic
----------------------------- */

app.post("/chat", authenticateToken, (req, res) => {

try {

const { symptom } = req.body;

/* Check if input is empty */
if (!symptom || symptom.trim() === "") {
return res.json({
reply: `<b>AI Health Assistant:</b><br><br>
Please describe your symptoms so I can help you.<br><br>
Examples:<br>
- fever<br>
- headache<br>
- stomach pain<br>
- cough and cold`
});
}

/* Gibberish check */
if (isGibberish(symptom)) {
return res.json({
reply: `<b>AI Health Assistant:</b><br><br>
I'm sorry, I couldn't understand your message.<br>
Please describe your symptoms clearly.<br><br>

Examples you can try:<br>
- fever<br>
- headache<br>
- stomach pain<br>
- cough`
});
}

/* Get health advice */
const reply = getHealthAdvice(symptom);

res.json({ reply });

} catch (error) {

console.error(error);

res.status(500).json({
reply: "Server error. Please try again."
});

}

});
function isGibberish(text){

// must contain letters and at least one real word length
if(!/^[a-zA-Z\s]+$/.test(text)){
return true;
}

if(text.length < 3){
return true;
}

const words = text.split(" ");

for(let w of words){
if(w.length > 2){
return false;
}
}

return true;
}


function getHealthAdvice(symptom){

symptom = symptom.toLowerCase();

/* FEVER */
if(symptom.includes("fever")){
return `<b>Condition:</b> Fever<br><br>
<b>Home Remedies:</b><br>
Drink warm fluids like herbal tea and soup.<br>
Take proper rest to allow the body to recover.<br>
Use a lukewarm sponge bath to reduce temperature.<br><br>
<b>Diet:</b><br>
Eat light foods like fruits, soups and boiled vegetables.<br><br>
<b>Precautions:</b><br>
Monitor temperature regularly and consult a doctor if fever persists.`;
}

/* COLD */
if(symptom.includes("cold")){
return `<b>Condition:</b> Common Cold<br><br>
<b>Home Remedies:</b><br>
Drink ginger tea or warm lemon water with honey.<br>
Take steam inhalation to clear nasal passages.<br>
Get plenty of rest to boost immunity.<br><br>
<b>Diet:</b><br>
Eat vitamin C rich fruits like oranges and lemons.<br><br>
<b>Precautions:</b><br>
Avoid cold drinks and sudden temperature changes.`;
}

/* COUGH */
if(symptom.includes("cough")){
return `<b>Condition:</b> Cough<br><br>
<b>Home Remedies:</b><br>
Drink warm water with honey and ginger.<br>
Steam inhalation can soothe throat irritation.<br>
Gargle with warm salt water to reduce throat inflammation.<br><br>
<b>Diet:</b><br>
Warm soups and herbal tea.<br><br>
<b>Precautions:</b><br>
Avoid dust, smoke and cold drinks.`;
}

/* HEADACHE */
if(symptom.includes("headache")){
return `<b>Condition:</b> Headache<br><br>
<b>Home Remedies:</b><br>
Rest in a quiet and dark room.<br>
Drink enough water to avoid dehydration.<br>
Apply a cold compress to the forehead.<br><br>
<b>Diet:</b><br>
Eat regular balanced meals.<br><br>
<b>Precautions:</b><br>
Reduce stress and screen exposure.`;
}

/* MIGRAINE */
if(symptom.includes("migraine")){
return `<b>Condition:</b> Migraine<br><br>
<b>Home Remedies:</b><br>
Rest in a dark quiet room.<br>
Apply a cold compress on the head.<br>
Practice relaxation exercises.<br><br>
<b>Diet:</b><br>
Avoid caffeine and processed foods.<br><br>
<b>Precautions:</b><br>
Avoid triggers like stress and lack of sleep.`;
}

/* STOMACH PAIN */
if(symptom.includes("stomach")){
return `<b>Condition:</b> Stomach Pain<br><br>
<b>Home Remedies:</b><br>
Drink warm water or ginger tea.<br>
Rest and avoid heavy meals.<br>
Use warm compress on the stomach.<br><br>
<b>Diet:</b><br>
Eat bananas, rice and light foods.<br><br>
<b>Precautions:</b><br>
Avoid spicy and oily foods.`;
}

/* GAS */
if(symptom.includes("gas")){
return `<b>Condition:</b> Gas or Bloating<br><br>
<b>Home Remedies:</b><br>
Drink warm lemon water.<br>
Walk after meals to improve digestion.<br>
Avoid overeating.<br><br>
<b>Diet:</b><br>
Eat fiber rich foods and fruits.<br><br>
<b>Precautions:</b><br>
Avoid carbonated drinks and fried foods.`;
}

/* ACIDITY */
if(symptom.includes("acidity")){
return `<b>Condition:</b> Acidity<br><br>
<b>Home Remedies:</b><br>
Drink cold milk or coconut water.<br>
Eat small frequent meals.<br>
Avoid lying down immediately after eating.<br><br>
<b>Diet:</b><br>
Fruits and vegetables are recommended.<br><br>
<b>Precautions:</b><br>
Avoid spicy and oily food.`;
}

/* DIARRHEA */
if(symptom.includes("diarrhea")){
return `<b>Condition:</b> Diarrhea<br><br>
<b>Home Remedies:</b><br>
Drink ORS solution to prevent dehydration.<br>
Eat bananas and plain rice.<br>
Rest well until recovery.<br><br>
<b>Diet:</b><br>
Light foods like soup and toast.<br><br>
<b>Precautions:</b><br>
Maintain hygiene and drink clean water.`;
}

/* CONSTIPATION */
if(symptom.includes("constipation")){
return `<b>Condition:</b> Constipation<br><br>
<b>Home Remedies:</b><br>
Drink plenty of water.<br>
Eat fiber rich foods.<br>
Exercise regularly.<br><br>
<b>Diet:</b><br>
Whole grains and leafy vegetables.<br><br>
<b>Precautions:</b><br>
Maintain regular eating habits.`;
}

/* VOMITING */
if(symptom.includes("vomiting")){
return `<b>Condition:</b> Vomiting<br><br>
<b>Home Remedies:</b><br>
Sip small amounts of water slowly.<br>
Drink ginger tea to settle stomach.<br>
Rest properly.<br><br>
<b>Diet:</b><br>
Eat bland foods like crackers or toast.<br><br>
<b>Precautions:</b><br>
Avoid oily foods until recovery.`;
}
if(symptom.includes("chest pain")){
return `<b>Condition:</b> Chest Pain<br><br>
<b>Home Remedies:</b><br>
Rest immediately and avoid physical activity.<br>
Take deep slow breaths.<br>
Drink warm water.<br><br>

<b>Diet:</b><br>
Eat light and low-fat foods.<br><br>

<b>Precautions:</b><br>
If chest pain is severe or spreads to arm, neck, or jaw, seek medical help immediately.`;
}
if(symptom.includes("leg pain")){
return `<b>Condition:</b> Leg Pain<br><br>
<b>Home Remedies:</b><br>
Rest the affected leg.<br>
Apply warm compress or massage gently.<br>
Do light stretching exercises.<br><br>

<b>Diet:</b><br>
Eat foods rich in calcium and potassium.<br><br>

<b>Precautions:</b><br>
Avoid overexertion and maintain proper posture while walking.`;
}
if(symptom.includes("knee pain")){
return `<b>Condition:</b> Knee Pain<br><br>
<b>Home Remedies:</b><br>
Apply ice or warm compress.<br>
Rest and avoid heavy activities.<br>
Do gentle knee exercises.<br><br>

<b>Diet:</b><br>
Calcium and vitamin D rich foods.<br><br>

<b>Precautions:</b><br>
Avoid climbing stairs excessively and maintain healthy body weight.`;
}
if(symptom.includes("shoulder pain")){
return `<b>Condition:</b> Shoulder Pain<br><br>
<b>Home Remedies:</b><br>
Apply ice pack or warm compress.<br>
Avoid heavy lifting.<br>
Do gentle shoulder stretches.<br><br>

<b>Diet:</b><br>
Protein and calcium rich foods.<br><br>

<b>Precautions:</b><br>
Maintain good posture and avoid sudden arm movements.`;
}
if(symptom.includes("muscle pain")){
return `<b>Condition:</b> Muscle Pain<br><br>
<b>Home Remedies:</b><br>
Take proper rest.<br>
Apply warm compress or massage.<br>
Stretch muscles gently.<br><br>

<b>Diet:</b><br>
Eat protein-rich foods and drink plenty of water.<br><br>

<b>Precautions:</b><br>
Avoid overexertion and warm up before exercise.`;
}
if(symptom.includes("hand pain")){
return `<b>Condition:</b> Hand Pain<br><br>
<b>Home Remedies:</b><br>
Rest the hand and avoid heavy work.<br>
Apply warm compress.<br>
Do gentle finger stretches.<br><br>

<b>Diet:</b><br>
Balanced diet with calcium and vitamin D.<br><br>

<b>Precautions:</b><br>
Avoid repetitive strain activities.`;
}
if(symptom.includes("insomnia") || symptom.includes("can't sleep") || symptom.includes("sleep problem")){
return `<b>Condition:</b> Insomnia (Sleep Disorder)<br><br>

<b>Home Remedies:</b><br>
Maintain a regular sleep schedule.<br>
Avoid using mobile or laptop before bedtime.<br>
Practice relaxation techniques like meditation.<br><br>

<b>Diet:</b><br>
Drink warm milk before sleeping.<br>
Avoid caffeine and heavy meals at night.<br><br>

<b>Precautions:</b><br>
Ensure a calm sleeping environment and consult a doctor if sleep problems continue for several weeks.`;
}
if(symptom.includes("depression") || symptom.includes("feeling sad")){
return `<b>Condition:</b> Depression<br><br>

<b>Home Remedies:</b><br>
Talk to trusted friends or family members.<br>
Engage in physical activities like walking or exercise.<br>
Practice meditation and mindfulness.<br><br>

<b>Diet:</b><br>
Eat balanced meals with fruits, vegetables and whole grains.<br><br>

<b>Precautions:</b><br>
Seek support from a mental health professional if symptoms persist or worsen.`;
}
if(symptom.includes("typhoid")){
return `<b>Condition:</b> Typhoid<br><br>

<b>Home Remedies:</b><br>
Take complete rest.<br>
Drink plenty of clean fluids.<br>
Maintain good hygiene and sanitation.<br><br>

<b>Diet:</b><br>
Eat soft foods like rice, soup and boiled vegetables.<br><br>

<b>Precautions:</b><br>
Consult a doctor immediately and complete prescribed medication.`;
}
if(symptom.includes("food poisoning") || symptom.includes("food poison")){
return `<b>Condition:</b> Food Poisoning<br><br>

<b>Home Remedies:</b><br>
Drink plenty of fluids or ORS solution.<br>
Rest properly.<br>
Avoid solid food until nausea reduces.<br><br>

<b>Diet:</b><br>
Eat light foods like bananas, rice and toast.<br><br>

<b>Precautions:</b><br>
Maintain proper food hygiene and consult a doctor if vomiting or diarrhea becomes severe.`;
}

if(symptom.includes("anxiety") || symptom.includes("stress")){
return `<b>Condition:</b> Anxiety or Stress<br><br>

<b>Home Remedies:</b><br>
Practice deep breathing exercises.<br>
Meditation and yoga can help calm the mind.<br>
Take regular breaks and relax.<br><br>

<b>Diet:</b><br>
Avoid excessive caffeine and sugary drinks.<br><br>

<b>Precautions:</b><br>
Talk to a healthcare professional if anxiety interferes with daily life.`;
}

if(symptom.includes("dehydration")){
return `<b>Condition:</b> Dehydration<br><br>

<b>Home Remedies:</b><br>
Drink water frequently.<br>
Consume ORS solution or coconut water.<br>
Rest in a cool place.<br><br>

<b>Diet:</b><br>
Eat fruits with high water content like watermelon and oranges.<br><br>

<b>Precautions:</b><br>
Avoid excessive sun exposure and maintain proper hydration.`;
}

/* SORE THROAT */
if(symptom.includes("sore throat")){
return `<b>Condition:</b> Sore Throat<br><br>
<b>Home Remedies:</b><br>
Gargle with warm salt water.<br>
Drink honey lemon tea.<br>
Use steam inhalation.<br><br>
<b>Diet:</b><br>
Warm soups and herbal tea.<br><br>
<b>Precautions:</b><br>
Avoid cold foods and drinks.`;
}

/* FLU */
if(symptom.includes("flu")){
return `<b>Condition:</b> Flu<br><br>
<b>Home Remedies:</b><br>
Rest properly and stay hydrated.<br>
Take steam inhalation for congestion.<br>
Drink herbal teas.<br><br>
<b>Diet:</b><br>
Eat fruits and soups.<br><br>
<b>Precautions:</b><br>
Avoid crowded places while sick.`;
}

/* ALLERGY */
if(symptom.includes("allergy")){
return `<b>Condition:</b> Allergy<br><br>
<b>Home Remedies:</b><br>
Avoid allergens such as dust or pollen.<br>
Use steam inhalation.<br>
Keep surroundings clean.<br><br>
<b>Diet:</b><br>
Eat vitamin C rich foods.<br><br>
<b>Precautions:</b><br>
Use antihistamines if prescribed.`;
}

/* ASTHMA */
if(symptom.includes("asthma")){
return `<b>Condition:</b> Asthma<br><br>
<b>Home Remedies:</b><br>
Practice breathing exercises.<br>
Avoid dusty or polluted areas.<br>
Keep inhaler available.<br><br>
<b>Diet:</b><br>
Eat fruits and vegetables.<br><br>
<b>Precautions:</b><br>
Avoid smoke and allergens.`;
}

/* BACK PAIN */
if(symptom.includes("back pain")){
return `<b>Condition:</b> Back Pain<br><br>
<b>Home Remedies:</b><br>
Apply hot compress.<br>
Do gentle stretching exercises.<br>
Rest and avoid heavy lifting.<br><br>
<b>Diet:</b><br>
Eat calcium rich foods.<br><br>
<b>Precautions:</b><br>
Maintain proper posture.`;
}

/* NECK PAIN */
if(symptom.includes("neck pain")){
return `<b>Condition:</b> Neck Pain<br><br>
<b>Home Remedies:</b><br>
Apply warm compress.<br>
Practice gentle neck stretches.<br>
Avoid long screen time.<br><br>
<b>Diet:</b><br>
Balanced nutritious diet.<br><br>
<b>Precautions:</b><br>
Maintain proper sitting posture.`;
}

/* JOINT PAIN */
if(symptom.includes("joint pain")){
return `<b>Condition:</b> Joint Pain<br><br>
<b>Home Remedies:</b><br>
Apply warm compress.<br>
Practice light exercises.<br>
Take rest when pain increases.<br><br>
<b>Diet:</b><br>
Eat foods rich in calcium and vitamin D.<br><br>
<b>Precautions:</b><br>
Avoid excessive strain on joints.`;
}

/* ARTHRITIS */
if(symptom.includes("arthritis")){
return `<b>Condition:</b> Arthritis<br><br>
<b>Home Remedies:</b><br>
Apply warm compress to joints.<br>
Practice gentle stretching.<br>
Maintain healthy body weight.<br><br>
<b>Diet:</b><br>
Eat anti-inflammatory foods like fish and nuts.<br><br>
<b>Precautions:</b><br>
Stay physically active.`;
}

/* DIABETES */
if(symptom.includes("diabetes")){
return `<b>Condition:</b> Diabetes<br><br>
<b>Home Remedies:</b><br>
Exercise daily.<br>
Monitor blood sugar regularly.<br>
Maintain healthy lifestyle habits.<br><br>
<b>Diet:</b><br>
Whole grains, vegetables and low sugar foods.<br><br>
<b>Precautions:</b><br>
Avoid sugary foods and drinks.`;
}

/* HIGH BLOOD PRESSURE */
if(symptom.includes("high blood pressure")){
return `<b>Condition:</b> High Blood Pressure<br><br>
<b>Home Remedies:</b><br>
Practice relaxation and breathing exercises.<br>
Exercise regularly.<br>
Maintain healthy weight.<br><br>
<b>Diet:</b><br>
Low salt diet and vegetables.<br><br>
<b>Precautions:</b><br>
Monitor BP regularly.`;
}

/* LOW BLOOD PRESSURE */
if(symptom.includes("low blood pressure")){
return `<b>Condition:</b> Low Blood Pressure<br><br>
<b>Home Remedies:</b><br>
Drink enough fluids.<br>
Rest if dizzy.<br>
Eat small frequent meals.<br><br>
<b>Diet:</b><br>
Balanced diet with adequate salt.<br><br>
<b>Precautions:</b><br>
Avoid sudden standing movements.`;
}

/* ANEMIA */
if(symptom.includes("anemia")){
return `<b>Condition:</b> Anemia<br><br>
<b>Home Remedies:</b><br>
Eat iron rich foods like spinach and lentils.<br>
Take vitamin C foods for better absorption.<br>
Rest properly.<br><br>
<b>Diet:</b><br>
Green leafy vegetables and fruits.<br><br>
<b>Precautions:</b><br>
Regular blood tests if symptoms persist.`;
}

/* SKIN RASH */
if(symptom.includes("skin rash")){
return `<b>Condition:</b> Skin Rash<br><br>
<b>Home Remedies:</b><br>
Keep skin clean and dry.<br>
Apply soothing lotions.<br>
Avoid scratching affected area.<br><br>
<b>Diet:</b><br>
Drink plenty of water.<br><br>
<b>Precautions:</b><br>
Avoid irritants and allergens.`;
}

/* ACNE */
if(symptom.includes("acne")){
return `<b>Condition:</b> Acne<br><br>
<b>Home Remedies:</b><br>
Wash face regularly.<br>
Use mild cleansers.<br>
Avoid touching face frequently.<br><br>
<b>Diet:</b><br>
Eat healthy fruits and vegetables.<br><br>
<b>Precautions:</b><br>
Avoid oily cosmetics.`;
}

/* EYE PAIN */
if(symptom.includes("eye pain")){
return `<b>Condition:</b> Eye Pain<br><br>
<b>Home Remedies:</b><br>
Rest eyes and avoid screens.<br>
Wash eyes with clean water.<br>
Use cold compress.<br><br>
<b>Diet:</b><br>
Eat vitamin A rich foods like carrots.<br><br>
<b>Precautions:</b><br>
Avoid rubbing eyes.`;
}

/* EAR PAIN */
if(symptom.includes("ear pain")){
return `<b>Condition:</b> Ear Pain<br><br>
<b>Home Remedies:</b><br>
Apply warm compress near ear.<br>
Rest and avoid water entry.<br>
Maintain ear hygiene.<br><br>
<b>Diet:</b><br>
Healthy balanced diet.<br><br>
<b>Precautions:</b><br>
Consult doctor if pain persists.`;
}

/* TOOTH PAIN */
if(symptom.includes("tooth pain")){
return `<b>Condition:</b> Tooth Pain<br><br>
<b>Home Remedies:</b><br>
Rinse mouth with warm salt water.<br>
Apply cold compress on cheek.<br>
Maintain oral hygiene.<br>

<b>Diet:</b><br>
Avoid sugary foods and drinks.<br><br>

<b>Precautions:</b><br>
Brush teeth twice daily and visit a dentist if pain continues.`;
}

/* DEFAULT RESPONSE */
return `<b>AI Health Assistant:</b><br><br>
I'm sorry, I don't have information about that symptom yet.<br><br>

Please try describing symptoms like:<br>
- fever<br>
- cough<br>
- headache<br>
- stomach pain<br>
- cold<br><br>

If symptoms are serious or persistent, please consult a doctor.`;

}

/* -----------------------------
   Start Server
----------------------------- */

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
console.log(`Server running on port ${PORT}`);
});