#include <QApplication>
#include <QIcon>
#include "EncryptDecryptWindow.h"

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setWindowIcon(QIcon(":/app_icon.ico"));

    EncryptDecryptWindow window;
    window.show();

    return app.exec();
}
