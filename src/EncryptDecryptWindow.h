#ifndef ENCRYPTDECRYPTWINDOW_H
#define ENCRYPTDECRYPTWINDOW_H

#include <QWidget>
#include <QPushButton>
#include <QLineEdit>
#include <QLabel>
#include <QTextEdit>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QString>

// 加密/解密窗口类
class EncryptDecryptWindow : public QWidget {
    Q_OBJECT
public:
    explicit EncryptDecryptWindow(QWidget* parent = nullptr);

private slots:
    void encryptText();
    void decryptText();
    void saveResults();
    void importExcel();

private:
    QLineEdit* inputText;
    QLineEdit* keyInput;
    QPushButton* encryptButton;
    QPushButton* decryptButton;
    QPushButton* saveButton;
    QTextEdit* encryptedResult;
    QTextEdit* decryptedResult;
    QPushButton* importExcelButton;
    std::string encryptedText;
    std::string decryptedText;
};

#endif // ENCRYPTDECRYPTWINDOW_H
