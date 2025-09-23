#include <QApplication>
#include <QWidget>
#include <QPushButton>
#include <QLineEdit>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFileDialog>
#include <QTextStream>
#include <QMessageBox>
#include <QString>
#include <QTextEdit>
#include <stdexcept>
#include <fstream>

// 扩展字符集，包括数字、字母和常见符号
const std::string EXTENDED_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.-";

int char_to_index(char c) {
    auto pos = EXTENDED_CHARSET.find(c);
    if (pos == std::string::npos) {
        throw std::invalid_argument("Invalid character in input string");
    }
    return static_cast<int>(pos);
}

char index_to_char(int x) {
    return EXTENDED_CHARSET[x % EXTENDED_CHARSET.size()];
}

std::string encrypt(const std::string& input, std::string_view key) {
    if (key.empty()) {
        throw std::invalid_argument("Key cannot be empty");
    }

    std::string encrypted;
    for (size_t i = 0; i < input.size(); ++i) {
        const int key_index = i % key.size();  // 循环使用 key
        const int value = (char_to_index(input[i]) ^ char_to_index(key[key_index])) % EXTENDED_CHARSET.size();
        encrypted += index_to_char(value);
    }
    return encrypted;
}

std::string decrypt(const std::string& encrypted, std::string_view key) {
    if (key.empty()) {
        throw std::invalid_argument("Key cannot be empty");
    }

    std::string decrypted;
    for (size_t i = 0; i < encrypted.size(); ++i) {
        const int key_index = i % key.size();  // 循环使用 key
        const int value = (char_to_index(encrypted[i]) ^ char_to_index(key[key_index])) % EXTENDED_CHARSET.size();
        decrypted += index_to_char(value);
    }
    return decrypted;
}

void save_to_file(const std::string& encrypted_text, const std::string& decrypted_text) {
    QString filename = QFileDialog::getSaveFileName(nullptr, "保存结果", "", "Text Files (*.txt);;All Files (*)");
    if (!filename.isEmpty()) {
        std::ofstream file(filename.toStdString());
        if (file.is_open()) {
            file << "加密结果:\n" << encrypted_text << "\n";
            file << "解密结果:\n" << decrypted_text << "\n";
            file.close();
            QMessageBox::information(nullptr, "保存成功", "结果已保存到文件中");
        }
        else {
            QMessageBox::warning(nullptr, "保存失败", "无法打开文件保存结果！");
        }
    }
}

class EncryptDecryptWindow : public QWidget {
    Q_OBJECT
public:
    EncryptDecryptWindow(QWidget* parent = nullptr) : QWidget(parent) {
        setWindowTitle("LiteCrypt");
        resize(480, 300);

        QVBoxLayout* layout = new QVBoxLayout(this);

        // 输入框和标签
        QHBoxLayout* inputLayout = new QHBoxLayout();
        QLabel* textLabel = new QLabel("文本: ");
        inputText = new QLineEdit();
        inputText = new QLineEdit();
        inputText->setFont(QFont("Arial", 14));  // 设置输入框字体大小
        inputLayout->addWidget(textLabel);
        inputLayout->addWidget(inputText);
        layout->addLayout(inputLayout);

        QHBoxLayout* keyLayout = new QHBoxLayout();
        QLabel* keyLabel = new QLabel("密钥: ");
        keyInput = new QLineEdit();
        keyInput->setText("relia123456"); // 默认密钥
        keyInput->setFont(QFont("Arial", 14));  // 设置输入框字体大小
        keyLayout->addWidget(keyLabel);
        keyLayout->addWidget(keyInput);
        layout->addLayout(keyLayout);

        // 按钮
        QHBoxLayout* buttonLayout = new QHBoxLayout();
        encryptButton = new QPushButton("加密");
        decryptButton = new QPushButton("解密");
        saveButton = new QPushButton("保存结果");

        // 设置按钮字体和高度
        QFont buttonFont("Arial", 16);
        encryptButton->setFont(buttonFont);
        decryptButton->setFont(buttonFont);
        saveButton->setFont(buttonFont);

        // 设置按钮高度
        encryptButton->setFixedHeight(40);
        decryptButton->setFixedHeight(40);
        saveButton->setFixedHeight(40);

        buttonLayout->addWidget(encryptButton);
        buttonLayout->addWidget(decryptButton);
        buttonLayout->addWidget(saveButton);
        layout->addLayout(buttonLayout);

        // 显示加密解密结果
        encryptedResult = new QTextEdit();
        encryptedResult->setPlaceholderText("加密结果...");
        encryptedResult->setReadOnly(true);  // 设置为只读，防止用户修改
        encryptedResult->setFont(QFont("Arial", 14));  // 设置显示结果字体大小
        decryptedResult = new QTextEdit();
        decryptedResult->setPlaceholderText("解密结果...");
        decryptedResult->setReadOnly(true);  // 设置为只读，防止用户修改
        decryptedResult->setFont(QFont("Arial", 14));  // 设置显示结果字体大小
        layout->addWidget(encryptedResult);
        layout->addWidget(decryptedResult);

        // 连接信号与槽
        connect(encryptButton, &QPushButton::clicked, this, &EncryptDecryptWindow::encryptText);
        connect(decryptButton, &QPushButton::clicked, this, &EncryptDecryptWindow::decryptText);
        connect(saveButton, &QPushButton::clicked, this, &EncryptDecryptWindow::saveResults);
    }

private slots:
    void encryptText() {
        std::string user_input = inputText->text().toStdString();
        std::string key = keyInput->text().toStdString();
        encryptedText = encrypt(user_input, key);
        encryptedResult->setText(QString::fromStdString(encryptedText));
    }

    void decryptText() {
        std::string user_input = inputText->text().toStdString();
        std::string key = keyInput->text().toStdString();
        decryptedText = decrypt(user_input, key);
        decryptedResult->setText(QString::fromStdString(decryptedText));
    }

    void saveResults() {
        save_to_file(encryptedText, decryptedText);
    }

private:
    QLineEdit* inputText;
    QLineEdit* keyInput;
    QPushButton* encryptButton;
    QPushButton* decryptButton;
    QPushButton* saveButton;
    QTextEdit* encryptedResult;
    QTextEdit* decryptedResult;
    std::string encryptedText;
    std::string decryptedText;
};

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setWindowIcon(QIcon(":/app_icon.ico"));

    EncryptDecryptWindow window;
    window.show();

    return app.exec();
}
#include "main.moc"