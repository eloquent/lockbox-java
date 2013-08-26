import de.johoop.jacoco4sbt._

import JacocoPlugin._

name := "lockbox"

libraryDependencies += "org.mockito" % "mockito-all" % "1.9.+" % "test"

javacOptions in (Compile, doc) ++= Seq("-windowtitle", "Lockbox API")

seq(testNGSettings:_*)

seq(jacoco.settings:_*)
