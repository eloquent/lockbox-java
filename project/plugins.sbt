resolvers ++= Seq(
    Classpaths.typesafeResolver,
    "scct-github-repository" at "http://mtkopone.github.com/scct/maven-repo"
)

addSbtPlugin("reaktor" % "sbt-scct" % "0.2-SNAPSHOT")

addSbtPlugin("com.github.theon" %% "xsbt-coveralls-plugin" % "0.0.3")

addSbtPlugin("de.johoop" % "sbt-testng-plugin" % "2.0.+")

addSbtPlugin("de.johoop" % "jacoco4sbt" % "2.0.+")
