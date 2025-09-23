#include "EncryptDecryptWindow.h"
#include <QMessageBox>
#include <QFileDialog>
#include <QFont>
#include <stdexcept>
#include <fstream>
#include <xlnt/xlnt.hpp>

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
        const char c = input[i];

        // 如果字符不在合法字符集内，跳过
        if (EXTENDED_CHARSET.find(c) == std::string::npos) {
            continue;  // 跳过这个字符
        }

        const int key_index = i % key.size();  // 循环使用 key
        const int value = (char_to_index(c) ^ char_to_index(key[key_index])) % EXTENDED_CHARSET.size();
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
        const char c = encrypted[i];

        // 如果字符不在合法字符集内，跳过
        if (EXTENDED_CHARSET.find(c) == std::string::npos) {
            continue;  // 跳过这个字符
        }

        const int key_index = i % key.size();  // 循环使用 key
        const int value = (char_to_index(c) ^ char_to_index(key[key_index])) % EXTENDED_CHARSET.size();
        decrypted += index_to_char(value);
    }
    return decrypted;
}

void save_to_file(const std::string& encrypted_text, const std::string& decrypted_text)try {
    const QString filename = QFileDialog::getSaveFileName(nullptr, "保存结果", "", "Excel Files (*.xlsx);;All Files (*)");

    if(filename.isEmpty()){
        QMessageBox::warning(nullptr, "选择文件失败", "请重新选择");
        return;
    }

    // --- 预处理：分割字符串 ---
    auto split_lines = [](const std::string& text) {
        std::vector<std::string> lines;
        std::istringstream iss(text);
        std::string line;
        while (std::getline(iss, line)) {
            lines.emplace_back(line);
        }
        return lines;
    };

    const std::vector<std::string> enc_lines = split_lines(encrypted_text);
    const std::vector<std::string> dec_lines = split_lines(decrypted_text);

    const std::size_t max_rows = std::max(enc_lines.size(), dec_lines.size());

    // --- Excel 写入 ---
    xlnt::workbook wb;
    xlnt::worksheet ws = wb.active_sheet();

    // 表头
    ws.cell("A1").value("加密结果");
    ws.cell("B1").value("解密结果");
    ws.cell("A1").font(xlnt::font().bold(true).size(20));
    ws.cell("B1").font(xlnt::font().bold(true).size(20));

    ws.row_properties(1).height = 30;
    ws.column_properties("A").width = 40;
    ws.column_properties("B").width = 40;

    // 数据行
    for (std::size_t i = 0; i < max_rows; ++i) {
        int row = static_cast<int>(i) + 2; // 数据从第2行开始

        if (i < enc_lines.size()) {
            ws.cell("A" + std::to_string(row)).value(enc_lines[i]);
            ws.cell("A" + std::to_string(row)).font(xlnt::font().size(15));
        }

        if (i < dec_lines.size()) {
            ws.cell("B" + std::to_string(row)).value(dec_lines[i]);
            ws.cell("B" + std::to_string(row)).font(xlnt::font().size(15));
        }

        ws.row_properties(row).height = 25;
    }

    wb.save(filename.toStdString());
    QMessageBox::information(nullptr, "保存成功", "结果已保存到Excel文件中");
}catch (xlnt::exception& e){
    QMessageBox::warning(nullptr, "保存Excel文件失败", e.what());
}

EncryptDecryptWindow::EncryptDecryptWindow(QWidget* parent) : QWidget(parent) {
    setWindowTitle("LiteCrypt");
    resize(480, 320);

    QVBoxLayout* layout = new QVBoxLayout(this);

    // 输入框和标签
    QHBoxLayout* inputLayout = new QHBoxLayout();
    QLabel* textLabel = new QLabel("文本: ");
    inputText = new QLineEdit();
    inputText->setFont(QFont("Arial", 14));
    inputLayout->addWidget(textLabel);
    inputLayout->addWidget(inputText);
    layout->addLayout(inputLayout);

    QHBoxLayout* keyLayout = new QHBoxLayout();
    QLabel* keyLabel = new QLabel("密钥: ");
    keyInput = new QLineEdit();
    keyInput->setText("relia123456"); // 默认密钥
    keyInput->setFont(QFont("Arial", 14));
    keyLayout->addWidget(keyLabel);
    keyLayout->addWidget(keyInput);
    layout->addLayout(keyLayout);

    // 按钮
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    encryptButton = new QPushButton("加密");
    decryptButton = new QPushButton("解密");
    saveButton = new QPushButton("保存结果");
    importExcelButton = new QPushButton("导入Excel");

    QFont buttonFont("Arial", 16);
    encryptButton->setFont(buttonFont);
    decryptButton->setFont(buttonFont);
    saveButton->setFont(buttonFont);
    importExcelButton->setFont(buttonFont);

    encryptButton->setFixedHeight(40);
    decryptButton->setFixedHeight(40);
    saveButton->setFixedHeight(40);
    importExcelButton->setFixedHeight(40);

    buttonLayout->addWidget(encryptButton);
    buttonLayout->addWidget(decryptButton);
    buttonLayout->addWidget(saveButton);
    buttonLayout->addWidget(importExcelButton);
    layout->addLayout(buttonLayout);

    // 显示加密解密结果
    encryptedResult = new QTextEdit();
    encryptedResult->setPlaceholderText("加密结果...");
    encryptedResult->setReadOnly(true);
    encryptedResult->setFont(QFont("Arial", 14));

    decryptedResult = new QTextEdit();
    decryptedResult->setPlaceholderText("解密结果...");
    decryptedResult->setReadOnly(true);
    decryptedResult->setFont(QFont("Arial", 14));

    layout->addWidget(encryptedResult);
    layout->addWidget(decryptedResult);

    connect(encryptButton, &QPushButton::clicked, this, &EncryptDecryptWindow::encryptText);
    connect(decryptButton, &QPushButton::clicked, this, &EncryptDecryptWindow::decryptText);
    connect(saveButton, &QPushButton::clicked, this, &EncryptDecryptWindow::saveResults);
    connect(importExcelButton, &QPushButton::clicked, this, &EncryptDecryptWindow::importExcel);
}

void EncryptDecryptWindow::encryptText() {
    std::string user_input = inputText->text().toStdString();
    std::string key = keyInput->text().toStdString();

    std::istringstream iss(user_input);
    std::string line;
    std::vector<std::string> encrypted_lines;

    while (std::getline(iss, line)) {
        encrypted_lines.push_back(encrypt(line, key));
    }

    // 拼接回一个字符串，用 \n 分隔
    encryptedText.clear();
    for (std::size_t i = 0; i < encrypted_lines.size(); ++i) {
        encryptedText += encrypted_lines[i];
        if (i + 1 != encrypted_lines.size()) {
            encryptedText += "\n";
        }
    }

    encryptedResult->setText(QString::fromStdString(encryptedText));
}

void EncryptDecryptWindow::decryptText() {
    std::string user_input = inputText->text().toStdString();
    std::string key = keyInput->text().toStdString();

    std::istringstream iss(user_input);
    std::string line;
    std::vector<std::string> decrypted_lines;

    while (std::getline(iss, line)) {
        decrypted_lines.push_back(decrypt(line, key));
    }

    // 拼接回一个字符串，用 \n 分隔
    decryptedText.clear();
    for (std::size_t i = 0; i < decrypted_lines.size(); ++i) {
        decryptedText += decrypted_lines[i];
        if (i + 1 != decrypted_lines.size()) {
            decryptedText += "\n";
        }
    }

    decryptedResult->setText(QString::fromStdString(decryptedText));
}

void EncryptDecryptWindow::saveResults() {
    save_to_file(encryptedText, decryptedText);
    // 清空Text
    encryptedResult->clear();
    decryptedResult->clear();
}

void EncryptDecryptWindow::importExcel(){
    // 使用Qt的文件对话框选择Excel文件
    const QString filename = QFileDialog::getOpenFileName(this, "选择Excel文件", "", "Excel Files (*.xlsx);;All Files (*)");
    if(filename.isEmpty()){
        QMessageBox::warning(this, "选择文件失败", "请重新选择");
        return;
    }
    // 使用xlnt库读取Excel文件第一列的内容
    std::vector<std::string> columnValues;
    try{
        xlnt::workbook wb;
        wb.load(filename.toStdString());
        xlnt::worksheet ws = wb.active_sheet();
        
        for(auto row : ws.rows()){
            if(row[0].has_value()){
                columnValues.emplace_back(row[0].to_string());
            }
        }
    } catch (const std::exception& e) {
        QMessageBox::warning(this, "导入Excel失败", e.what());
    }

    // 写入输入框
    inputText->setText(QString::fromStdString(
        std::accumulate(columnValues.begin(), columnValues.end(), std::string(),
            [](const std::string& a, const std::string& b) {
                return a + (a.empty() ? "" : "\n") + b;
            })
    ));
}
