import pandas as pd
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


# ---------------- TRAINING DATA ----------------

data = {
    "email": [
        "Urgent! Your bank account has been suspended. Click here immediately to verify your password.",
        "Congratulations! You won a prize. Click here to claim your reward now.",
        "Your account has been blocked. Send your OTP to verify your identity.",
        "URGENT: Your payment failed. Login immediately to update your bank account.",
        "You have won a lottery. Claim your prize by clicking this link.",
        "Security alert! Confirm your identity immediately or your account will be closed.",

        "Hello John, your meeting is scheduled for tomorrow at 10 AM.",
        "Your Amazon order has been shipped and will arrive tomorrow.",
        "Dear student, your examination timetable has been uploaded.",
        "Your electricity bill payment was successful.",
        "Thank you for your purchase. Your order has been confirmed.",
        "Your appointment has been successfully scheduled."
    ],

    "label": [
        "fake",
        "fake",
        "fake",
        "fake",
        "fake",
        "fake",

        "genuine",
        "genuine",
        "genuine",
        "genuine",
        "genuine",
        "genuine"
    ]
}


df = pd.DataFrame(data)


# ---------------- TEXT VECTORIZATION ----------------

vectorizer = TfidfVectorizer(
    lowercase=True,
    stop_words="english"
)

X = vectorizer.fit_transform(df["email"])
y = df["label"]


# ---------------- TRAIN MODEL ----------------

model = LogisticRegression()

model.fit(X, y)


# ---------------- SAVE MODEL ----------------

joblib.dump(model, "model/email_model.pkl")
joblib.dump(vectorizer, "model/tfidf_vectorizer.pkl")


print("AI model trained successfully!")
print("Model saved inside model/ folder.")