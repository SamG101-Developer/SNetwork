import sys
from PyQt6 import QtWidgets, QtCore, QtGui
from PyQt6 import Qt3DCore
from PyQt6 import Qt3DExtras
from PyQt6 import Qt3DRender


class SceneModifier(QtCore.QObject):
    def __init__(self, root_entity=None):
        super().__init__()
        self.m_rootEntity = root_entity

        # MESH
        self.sphereMesh = Qt3DExtras.QSphereMesh()
        self.sphereMesh.setRadius(6)
        self.sphereMesh.setRings(40)
        self.sphereMesh.setSlices(10)

        # MATERIAL
        gradient = QtGui.QLinearGradient(0, 0, 0, 1)
        gradient.setStops([(0, QtCore.Qt.GlobalColor.white), (1, QtCore
                                                              .Qt.GlobalColor.black)])
        self.sphereMaterial = Qt3DExtras.QPhongAlphaMaterial()
        self.sphereMaterial.setDiffuse(QtGui.QColor("#ddddff"))
        self.sphereMaterial.setAmbient(QtGui.QColor("#44bbff"))
        self.sphereMaterial.setShininess(50)
        self.sphereMaterial.setAlpha(1)

        # TRANSFORM
        self.sphereTransform = Qt3DCore.QTransform()
        self.sphereTransformTimer = QtCore.QTimer()
        self.sphereTransformTimer.setSingleShot(False)
        self.sphereTransformTimer.timeout.connect(self._rotate)
        self.sphereTransformTimer.start(round(1000 / 60))

        # ENTITY
        self.sphere = Qt3DCore.QEntity(self.m_rootEntity)
        self.sphere.addComponent(self.sphereMesh)
        self.sphere.addComponent(self.sphereMaterial)
        self.sphere.addComponent(self.sphereTransform)

    def _rotate(self):
        self.sphereTransform.setRotationY(self.sphereTransform.rotationY() + 1)


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)

    view = Qt3DExtras.Qt3DWindow()
    view.defaultFrameGraph().setClearColor(QtGui.QColor("#4d4d4f"))

    rootEntity = Qt3DCore.QEntity()

    # CAMERA
    cameraEntity = view.camera()
    cameraEntity.lens().setPerspectiveProjection(45.0, 16.0 / 9.0, 0.1, 1000.0)
    cameraEntity.setPosition(QtGui.QVector3D(0, 0, 20.0))
    cameraEntity.setUpVector(QtGui.QVector3D(0, 1, 0))
    cameraEntity.setViewCenter(QtGui.QVector3D(0, 0, 0))

    # LIGHT
    lightEntity = Qt3DCore.QEntity(rootEntity)
    light = Qt3DRender.QPointLight(lightEntity)
    light.setColor(QtGui.QColor("white"))
    light.setIntensity(2)
    lightEntity.addComponent(light)

    lightTransform = Qt3DCore.QTransform(lightEntity)
    lightTransform.setTranslation(cameraEntity.position())
    lightEntity.addComponent(lightTransform)

    # CAMERA CONTROLLER
    camController = Qt3DExtras.QFirstPersonCameraController(rootEntity)
    camController.setCamera(cameraEntity)

    # ADD OBJECTS
    modifier = SceneModifier(rootEntity)
    view.setRootEntity(rootEntity)
    view.showMaximized()

    sys.exit(app.exec())
