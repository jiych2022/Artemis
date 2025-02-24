package org.codeminers

import io.shiftleft.codepropertygraph.generated.{Cpg, NodeTypes}
import io.shiftleft.codepropertygraph.generated.nodes.{Method, Mynodetype}
import io.shiftleft.semanticcpg.language.*
import flatgraph.help.{Doc, DocSearchPackages, Traversal, TraversalSource}

import scala.jdk.CollectionConverters.IteratorHasAsScala
import scala.util.matching.Regex

package object standalone {

  // provides package names to search for @Doc annotations etc
  implicit val docSearchPackages: DocSearchPackages =
    Cpg.defaultDocSearchPackage
      .withAdditionalPackage(this.getClass.getPackageName)

  /** Example of a custom language step
    */
  implicit class MynodetypeSteps(val traversal: Iterator[Mynodetype]) extends AnyVal {
    def myCustomStep: Iterator[Mynodetype] = {
      println("custom step executed")
      traversal
    }
  }

  @Traversal(elementType = classOf[Method])
  implicit class CustomMethodSteps(val traversal: Iterator[Method]) extends AnyVal {
    @Doc("custom step on method as an example", "a veeery long description again")
    def customMethodStep: Iterator[String] =
      traversal.flatMap(_.parameter.name)
  }

  /** Example implicit conversion that forwards to the `StandaloneStarters` class
    */
  implicit def toStandaloneStarters(cpg: Cpg): StandaloneStarters =
    new StandaloneStarters(cpg)

  /** Example of custom node type starters */
  @TraversalSource
  class StandaloneStarters(cpg: Cpg) {
    @Doc("custom starter step as an example", "a veeery long description")
    def customStarterStep: Iterator[String] =
      cpg.method.parameter.name
  }

  def extractFileAndLineInfo(input: String): List[(String, Int)] = {
    var fileLines: List[(String, Int)] = List()

    // Define the regex to match `/path/to/file.php:line` and `/path/to/file.php +line;`
    val pattern: Regex = """((/[\S/]+\.php):(\d+))|((/[\S/]+\.php)\s*\+(\d+))""".r

    // Find all matches in the input string
    val matches = pattern.findAllMatchIn(input)

    // Handle colon-separated and plus-separated formats
    matches.foreach { m =>
      if (m.group(2) != null && m.group(3) != null) {
        fileLines = fileLines :+ (m.group(2), m.group(3).toInt)
      } else if (m.group(5) != null && m.group(6) != null) {
        fileLines = fileLines :+ (m.group(5), m.group(6).toInt)
      }
    }
    fileLines
  }
}
