import numpy as np
import pandas as pd
import feature_extraction
import os
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import BaggingClassifier
from sklearn.model_selection import train_test_split
from flask import jsonify
import pickle
import content_analysis

# Fungsi untuk memeriksa jika model sudah ada
def check_model_exists():
    return os.path.exists('phishing_model.pkl')

# Fungsi untuk menyimpan model
def save_model(model):
    with open('phishing_model.pkl', 'wb') as f:
        pickle.dump(model, f)

# Fungsi untuk memuat model
def load_model():
    with open('phishing_model.pkl', 'rb') as f:
        return pickle.load(f)

# Fungsi untuk melatih model
def train_model():
    try:
        # Mengecek apakah dataset ada
        if not os.path.exists("dataset_pi.csv"):
            print("Dataset tidak ditemukan. Gunakan model default.")
            # Buat model sederhana dengan hanya menggunakan 30 fitur
            # Return 1 jika bukan phishing, -1 jika phishing
            model = BaggingClassifier(DecisionTreeClassifier(), max_samples=1.0, max_features=1.0, n_estimators=10)
            # Jika dataset tidak ada, kita buat data dummy untuk training
            X_dummy = np.random.randint(-1, 2, size=(100, 30))
            y_dummy = np.random.randint(0, 2, size=(100,))
            model.fit(X_dummy, y_dummy)
            return model
        
        # Importing dataset
        df = pd.read_csv("dataset_pi.csv")
        
        # Memeriksa apakah dataset kosong
        if df.empty:
            print("Dataset kosong. Gunakan model default.")
            model = BaggingClassifier(DecisionTreeClassifier(), max_samples=1.0, max_features=1.0, n_estimators=10)
            X_dummy = np.random.randint(-1, 2, size=(100, 30))
            y_dummy = np.random.randint(0, 2, size=(100,))
            model.fit(X_dummy, y_dummy)
            return model
            
        # Memisahkan features dan labels
        try:
            x = df.iloc[:,:-1]
            y = df.iloc[:,-1]
            
            # Handle jika jumlah feature tidak sesuai
            if x.shape[1] != 30:
                print(f"Jumlah feature dalam dataset ({x.shape[1]}) tidak sesuai dengan yang diharapkan (30)")
                # Buat data dummy jika tidak sesuai
                X_dummy = np.random.randint(-1, 2, size=(100, 30))
                y_dummy = np.random.randint(0, 2, size=(100,))
                model = BaggingClassifier(DecisionTreeClassifier(), max_samples=1.0, max_features=1.0, n_estimators=10)
                model.fit(X_dummy, y_dummy)
                return model
                
            # Melakukan Training pada model
            x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=7)
            bg = BaggingClassifier(DecisionTreeClassifier(), max_samples=1.0, max_features=1.0, n_estimators=100)
            bg.fit(x_train, y_train)
            score = bg.score(x_test, y_test)
            print('Akurasi model: ', score*100, '%')
            return bg
        except Exception as e:
            print(f"Error saat memproses dataset: {e}")
            # Buat model default jika terjadi error
            model = BaggingClassifier(DecisionTreeClassifier(), max_samples=1.0, max_features=1.0, n_estimators=10)
            X_dummy = np.random.randint(-1, 2, size=(100, 30))
            y_dummy = np.random.randint(0, 2, size=(100,))
            model.fit(X_dummy, y_dummy)
            return model
            
    except Exception as e:
        print(f"Error saat melatih model: {e}")
        # Buat model default jika terjadi error
        model = BaggingClassifier(DecisionTreeClassifier(), max_samples=1.0, max_features=1.0, n_estimators=10)
        X_dummy = np.random.randint(-1, 2, size=(100, 30))
        y_dummy = np.random.randint(0, 2, size=(100,))
        model.fit(X_dummy, y_dummy)
        return model

def getResult(url):
    try:
        # Step 1: Periksa menggunakan analisis konten terlebih dahulu 
        try:
            print(f"Melakukan analisis konten pada URL: {url}")
            content_result = content_analysis.check_phishing_content(url)
            
            # Jika ini adalah alat keamanan yang dikenal atau analisis kontennya sangat yakin.
            if not content_result["is_phishing"] and (
                "security tool" in " ".join(content_result["reasons"]) or 
                content_result["score"] < 10
            ):
                print("Diidentifikasi sebagai website aman berdasarkan analisis konten")
                print(f"Alasan: {content_result['reasons']}")
                return content_result["message"]
                
            # Jika analisis konten sangat yakin itu adalah phishing
            if content_result["is_phishing"] and content_result["score"] > 75:
                print("Diidentifikasi sebagai website phishing berdasarkan analisis konten")
                print(f"Alasan: {content_result['reasons']}")
                return content_result["message"]
                
            # Kalau tidak, lanjutkan dengan prediksi model ML
            print("Hasil analisis konten tidak meyakinkan, lanjut ke proses prediksi model ML")
        except Exception as e:
            print(f"Error pada analisis konten: {e}")
            # Lanjutkan dengan model ML jika analisis konten gagal
        
        # Step 2: Pemeriksaan model ML standar (kode yang ada)
        # Cek apakah model sudah ada atau perlu dilatih
        if check_model_exists():
            print("Memuat model yang sudah ada...")
            model = load_model() #dataset
        else:
            print("Melatih model baru...")
            model = train_model()
            save_model(model)
            
        # Generate dataset dari URL
        print(f"Menganalisis URL: {url}")
        X_new = feature_extraction.generate_data_set(url)
        
        # Memeriksa jumlah fitur
        if len(X_new) != 30:
            print(f"Warning: Jumlah fitur yang dihasilkan ({len(X_new)}) tidak sesuai dengan yang diharapkan (30)")
            # Tambahkan nilai default jika kurang dari 30
            while len(X_new) < 30:
                X_new.append(1)  # Default to safe value
            # Potong jika lebih dari 30
            X_new = X_new[:30]
            
        X_new = np.array(X_new).reshape(1, -1)
        
        # Prediksi menggunakan model ML
        ml_prediction = model.predict(X_new)
        # Konsistensi label: -1 = Phishing, 1 = Legitimate
        ml_result = "Waspada Terindikasi Website Phishing" if ml_prediction[0] == -1 else "Bukan Website Phishing"
        print(f"Hasil prediksi model ML: {ml_result}")
        
        # Step 3: Pemeriksaan berbasis konten jika model ML mendeteksi sebagai phishing (pemeriksaan ganda)
        if ml_prediction[0] == -1:  # Jika ML model predicts phishing
            try:
                # Jika content_result belum didefinisikan (karena exception sebelumnya)
                if not 'content_result' in locals():
                    content_result = content_analysis.check_phishing_content(url)
                
                # Jika content analysis sangat tidak cocok dengan ML model
                if not content_result["is_phishing"] and content_result["score"] < 20:
                    print("Model ML mendeteksi sebagai phishing, tapi analisis konten tidak menemukan indikator")
                    print(f"Alasan analisis konten: {content_result['reasons']}")
                    
                    # Periksa jika itu adalah security tool
                    if any("security tool" in reason.lower() for reason in content_result["reasons"]):
                        print("Website terdeteksi sebagai alat keamanan yang sah")
                        return "Bukan Website Phishing (Security Tool)"
            except Exception as e:
                print(f"Error pada analisis konten kedua: {e}")
        
        # Return final result (konsisten: -1 = phishing, 1 = aman)
        if ml_prediction[0] == -1:
            print("Waspada Terindikasi Website Phishing")
            return "Waspada Terindikasi Website Phishing"
        else:
            print("Bukan Website Phishing")
            return "Bukan Website Phishing"
            
    except Exception as e:
        print(f"Error saat melakukan prediksi: {e}")
        print("Waspada Terindikasi Website Phishing (default untuk case error)")
        return "Waspada Terindikasi Website Phishing"

def getDetailedResult(url):
    """
    Get detailed phishing detection results with reasons
    
    Args:
        url (str): URL to analyze
        
    Returns:
        dict: Detailed results including ML prediction and content analysis
    """
    results = {
        "url": url,
        "final_result": "",
        "ml_prediction": "",
        "content_analysis": {}
    }
    
    try:
        # Content Analysis
        content_result = content_analysis.check_phishing_content(url)
        results["content_analysis"] = content_result
        
        # ML Model
        if check_model_exists():
            model = load_model()
        else:
            model = train_model()
            save_model(model)
            
        X_new = feature_extraction.generate_data_set(url)
        if len(X_new) != 30:
            while len(X_new) < 30:
                X_new.append(1)
            X_new = X_new[:30]
            
        #Prediksi Menggunakan Model Machine Learning
        X_new = np.array(X_new).reshape(1, -1)
        ml_prediction = model.predict(X_new)
        results["ml_prediction"] = "Bukan Website Phishing" if ml_prediction[0] == 1 else "Waspada Terindikasi Website Phishing"
        
        # Determine final result
        if content_result["is_phishing"] and ml_prediction[0] == -1:
            # Kedua metode tersebut setuju jika phishing
            results["final_result"] = "Waspada Terindikasi Website Phishing"
        elif not content_result["is_phishing"] and ml_prediction[0] == 1:
            # Kedua metode tersebut setuju jika aman
            results["final_result"] = "Bukan Website Phishing"
        elif "security tool" in " ".join(content_result["reasons"]).lower():
            # Override untuk security tools
            results["final_result"] = "Bukan Website Phishing (Security Tool)"
        elif content_result["score"] < 20 and ml_prediction[0] == -1:
            # Content analysis percaya jika aman, tapi ML berfikir itu phishing
            results["final_result"] = "Bukan Website Phishing (Content Analysis Override)"
        elif content_result["score"] > 75 and ml_prediction[0] == 1:
            # Content analysis percaya itu phishing, tapi ML berfikir itu aman
            results["final_result"] = "Waspada Terindikasi Website Phishing (Content Analysis Override)"
        else:
            # When in doubt, be cautious
            results["final_result"] = "Waspada Terindikasi Website Phishing" 
            
    except Exception as e:
        results["error"] = str(e)
        results["final_result"] = "Waspada Terindikasi Website Phishing (Error)"
        
    return results

if __name__ == "__main__":
    import sys
    import json
    if len(sys.argv) > 2 and sys.argv[2] == 'detailed':
        url = sys.argv[1]
        result = getDetailedResult(url)
        # Hapus semua print debug/log sebelum print JSON
        print(json.dumps(result, ensure_ascii=False))
    elif len(sys.argv) > 1:
        url = sys.argv[1]
        print(getResult(url))
    else:
        print("URL tidak diberikan.")