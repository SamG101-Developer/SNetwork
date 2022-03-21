from PyQt6.QtWidgets import QSplashScreen, QApplication
from PyQt6.QtCore import QVariantAnimation


class splash_screen(QSplashScreen):
    def __init__(self):
        QSplashScreen.__init__(self)

        self._animation = QVariantAnimation(self)
        self._animation.setS
