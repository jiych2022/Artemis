package org.codeminers.standalone

import flatgraph.DiffGraphBuilder
import io.joern.dataflowengineoss.language.{cfgNodeToMethodsQp, expressionMethods, toExtendedCfgNode}
import io.joern.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.joern.php2cpg.{Config, Php2Cpg}
import io.joern.x2cpg.X2Cpg.applyDefaultOverlays
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{Call, CfgNode, Expression, Identifier, Literal, NewMynodetype, StoredNode}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.layers.LayerCreatorContext
import org.apache.logging.log4j.core.config.Configurator
import io.joern.x2cpg.frontendspecific.php2cpg

import java.io.FileInputStream
import java.util.Properties
import scala.sys.process.*
import scala.util.{Failure, Success}

object PruningMain {

  implicit val resolver: ICallResolver = NoResolve
  implicit val context: EngineContext  = EngineContext()
  var ostrichPath                      = "/home/jiych1/IdeaProjects/ostrich/ostrich"

  def loadProperties(filePath: String): Properties = {
    val properties = new Properties()
    val fileStream = new FileInputStream(filePath)
    try {
      properties.load(fileStream)
    } finally {
      fileStream.close() // Ensure the file is properly closed
    }
    properties
  }

  def main(args: Array[String]): Unit = {
    Configurator.setRootLevel(org.apache.logging.log4j.Level.ERROR)
    if (args.length != 1) {
      println("No argument")
      return
    }
    val baseConfig = loadProperties("config.properties")
    val phpParser = baseConfig.getProperty("config.phpparserPath")
    ostrichPath = baseConfig.getProperty("config.ostrichPath")

    val input = args(0)
    if (!input.contains("lhc_web") && !input.contains("ifm")) {
      return
    }
    val fileLines = extractFileAndLineInfo(input)
    //println(fileLines)
    // For each absolute path, only preserve file name, save the result pair in a new list
    val taintedLines = fileLines.map { case (file, line) =>
      val fileName = file.split("/").last
      (fileName, line)
    }
    // Create a temp folder if not exist. If exist, clear the folder
    val tempDir = "/tmp/fp-check"
    val tempDirFile = new java.io.File(tempDir)
    if (!tempDirFile.exists()) {
      tempDirFile.mkdir()
    } else {
      tempDirFile.listFiles().foreach(_.delete())
    }
    // For each file listed in fileLines, copy the file to temp folder, ignore existing files
    for ((file, lines) <- fileLines) {
      val sourceFile = s"$file"
      val cmd = s"cp $sourceFile $tempDir"
      cmd.!!
    }

    val config = Config()
      .withInputPath(tempDir)
      .withPhpParserBin(
        phpParser
      )

    println("Initializing Joern")
    val cpgOrException = Php2Cpg().createCpg(config)
    val taintedPairs   = Map()

    cpgOrException match {
      case Success(cpg) =>
        applyDefaultOverlays(cpg)
        php2cpg.postProcessingPasses(cpg).foreach(_.createAndApply())
        val dataflowLayer = new OssDataFlow(new OssDataFlowOptions())
        val context       = new LayerCreatorContext(cpg)
        dataflowLayer.run(context)
        println(cpg.graph.nodeCount)
        //println("Running custom queries")

        runQuery(cpg, taintedLines)

//        val result = computeExpectedReturnValueForCall(cpg, 31, "false")
//        println(result)
      case Failure(exception) =>
        //println("No FP identified")
        //println("[FAILED]")
        //println(exception)
    }
  }

  private def runQuery(cpg: Cpg, taintedLines: List[(String, Int)]): Unit = {
    var condPair = Map[Int, String]()
    // For each tainted line, find what controls them
    for (line <- taintedLines) {
      condPair = extractConds(cpg, condPair, line)
    }

    // Print the result
    for ((line, label) <- condPair) {
      // println(s"Cond on $line should be $label")
    }
    identifyImpossibleConds(cpg, condPair, taintedLines)
    identifyUseOfInArray(cpg, condPair, taintedLines)

    condPair = extractCondsFromCalls(cpg, condPair, taintedLines)
    //println(condPair)
    verifyCond(cpg, condPair)
  }

  private def verifyCond(cpg: Cpg, condPair: Map[Int, String]): Unit = {
    for ((line, label) <- condPair) {
      val cfgNode             = cpg.cfgNode.lineNumber(line).l
      val targetFunctionNames = List("strpos", "stripos", "strstr", "stristr", "strlen", "preg_match", "preg_match_all")
      val targetCalls         = cfgNode.containsCallTo("strpos").isCall.l
      if (targetCalls.nonEmpty) {
        val opCall   = targetCalls.head
        val operator = opCall.name
        operator match {
          case "<operator>.notIdentical" =>
            val rhs    = opCall.argument.argumentIndex(2).head
            val rhsVal = resolveArgumentValue(cpg, rhs, List()).getOrElse("-9999")
            if (rhsVal != "-9999") {
              val lhsList = opCall.argument.argumentIndex(1).isCall.l
              if (lhsList.size == 1) {
                val strposCall   = lhsList.head
                val typeFullName = strposCall.argument.argumentIndex(2).isIdentifier.head.typeFullName
                if (typeFullName == "Iterator.current-><returnValue>") {
                  val forLine    = strposCall.inAst.isControlStructure.controlStructureType("FOR").lineNumber.head
                  val arrayInits = cpg.cfgNode.lineNumber(forLine).code("\\$tmp.*=.*").l
                  val values = arrayInits.flatMap(init => {
                    val value = init.code.split("=")(1).trim.stripPrefix("\"").stripSuffix("\"")
                    if (value != "array()") {
                      //println(s"Checking $value")
                      Some(value)
                    } else {
                      None
                    }
                  })
                  if (values.nonEmpty) {
                    values.foreach(value => {
                      val result = constructStrposSMT(value)
                      if (result.contains("unsat")) {
                        println(s"[[FP]]Condition on line $line is impossible")
                      }
                    })
                  }
                }
              }
            }
          case _ =>
        }
      }
    }
  }

  private def constructStrposSMT(value: String): String = {
    val template =s"""(set-logic QF_S)
         |
         |(set-option :produce-models true)
         |
         |(declare-const w String)
         |
         |(assert (str.in_re w (re.from_ecma2020 '^[a-zA-Z]+://[a-zA-Z0-9.-]+\\.[a-zA-Z]+$$')))
         |(assert  (= (str.indexof w \"${value}\" 0) (- 1)))
         |
         |(check-sat)
         |(get-model)
         |
         |""".stripMargin
    // Save to tmp file
    val tmpFile = "/tmp/strpos.smt2"
    val writer  = new java.io.PrintWriter(new java.io.File(tmpFile))
    writer.write(template)
    writer.close()
    // Run OSTRICH
    val cmd = s"$ostrichPath +incremental $tmpFile 2>&1"
    val result = scala.sys.process.Process(cmd).!!(ProcessLogger(_ => ()))
    result
  }

  private def extractConds(cpg: Cpg, condPair: Map[Int, String], pair: (String, Int)): Map[Int, String] = {
    var ret              = condPair
    val filename         = pair(0)
    val line             =  pair(1)
    var node             = cpg.cfgNode.lineNumber(line).l
    // Remove node whose file is not filename
    node = node.filter(_.file.name(filename).nonEmpty)
    val controlling      = node.controlledBy.l
    val controllingNodes = controlling.astParent.isControlStructure.isIf.l
    // For each ast of controlling node
    for (controllingNode <- controllingNodes) {
      // Check the whenTrue
      val whenTrue = controllingNode.whenTrue.ast.l
      // Whether target line is contained in whenTrue
      var label = "false"
      if (whenTrue.exists(_.lineNumber.contains(line))) {
        label = "true"
      }
      if (!ret.contains(controllingNode.lineNumber.getOrElse(-1))) {
        ret += (controllingNode.lineNumber.getOrElse(-1) -> label)
      }
    }
    return ret
  }

  private def extractCondsFromCalls(cpg: Cpg, pair: Map[Int, String], lines: List[(String, Int)]): Map[Int, String] = {
    var ret = pair
    for ((line, label) <- pair) {
      // println(s"Checking line $line with $label")
      val cfgNode       = cpg.cfgNode.lineNumber(line).l
      val targetMethods = cfgNode.isCall.callee.isExternal(false).l
      if (targetMethods.size == 1) {
        val method         = targetMethods.head
        val expectedOption = computeExpectedReturnValueForCall(cpg, line, label)
        //println(s"Expected: $expectedOption")
        expectedOption match {
          case Some(expected) => {
            // Extract return nodes
            val returnNodes = method.cfgNode.isReturn.l
            val expectedReturnNodes = returnNodes.filter { returnNode =>
              val returnCode = returnNode.code
              val returnValue = returnCode match {
                case "return true"  => Some(true)
                case "return false" => Some(false)
                case _              => None
              }
              returnValue match {
                case Some(value) => value == expected
                case None        => false
              }
            }
            if (expectedReturnNodes.nonEmpty) {
              // For each expected return node, extract conditions and labels
              for (expectedReturnNode <- expectedReturnNodes) {
                val filename = expectedReturnNode.file.name.headOption.getOrElse("")
                val res = extractConds(cpg, pair, (filename, expectedReturnNode.lineNumber.getOrElse(-1)))
                // For each extracted pair, update the result
                for ((line, label) <- res) {
                  if (!ret.contains(line)) {
                    ret += (line -> label)
                  }
                }
              }
            }
          }
          case None => {}
        }
      }
    }
    return ret
  }

  /** Given a conditional line, compute the expected boolean return value of functions called inside
    *
    * @param cpg
    *   CPG
    * @param line
    *   Line of condition that contains a user function call
    * @param overall
    *   Overall label
    * @return
    *   Expected boolean return value
    */
  private def computeExpectedReturnValueForCall(cpg: Cpg, line: Int, overall: String): Option[Boolean] = {
    var expected = overall match {
      case "true"  => true
      case "false" => false
    }
    val node       = cpg.cfgNode.lineNumber(line).l
    val conditions = node.isCall.headOption

    if (conditions.nonEmpty) {
      val condition = conditions.get
      condition.name match {
        case "<operator>.logicalNot" =>
          val target = condition.argument.isCall.headOption
          target match {
            case Some(t) =>
              val targetName = t.name
              if (targetName.startsWith("<operator>.logical")) {
                return None
              }
              targetName match {
                case "<operator>.notEquals" | "<operator>.notIdentical" => expected = !expected
                case _                                                  =>
              }
            case None => return None
          }
          return Some(!expected)
        case "<operator>.equals" | "<operator>.identical" =>
          val lhs = condition.argument.argumentIndex(1).isLiteral.headOption
          val rhs = condition.argument.argumentIndex(2).isLiteral.headOption
          if (lhs.isEmpty && rhs.isEmpty) {
            return None
          }
          // Get the literal
          val literal = if (lhs.nonEmpty) lhs.get else rhs.get
          val value   = resolveArgumentValue(cpg, literal, List())
          if (value.isEmpty) {
            return None
          }
          val literalValue = value.get
          literalValue match
            case bool: Boolean =>
              // if expected = ture return bool, otherwise return !bool
              return Some(if (expected) bool else !bool)
            case _ => return None
        case "<operator>.notEquals" | "<operator>.notIdentical" =>
          val lhs = condition.argument.argumentIndex(1).isLiteral.headOption
          val rhs = condition.argument.argumentIndex(2).isLiteral.headOption
          if (lhs.isEmpty && rhs.isEmpty) {
            return None
          }
          // Get the literal
          val literal = if (lhs.nonEmpty) lhs.get else rhs.get
          val value   = resolveArgumentValue(cpg, literal, List())
          if (value.isEmpty) {
            return None
          }
          val literalValue = value.get
          literalValue match
            case bool: Boolean =>
              return Some(if (expected) !bool else bool)
            case _ => return None
        case _ => return None
      }
    }
    None

  }

  private def identifyUseOfInArray(cpg: Cpg, pair: Map[Int, String], pairs: List[(String,Int)]): Unit = {
    val lines = pairs.map(_._2)
    for ((line, label) <- pair) {
      val cfgNode     = cpg.cfgNode.lineNumber(line).l
      val targetCalls = cfgNode.isCall.name("in_array").l
      if (targetCalls.nonEmpty) {
        val arg = targetCalls.argument.argumentIndex(1).head
        if (lines.exists(l => cpg.cfgNode.lineNumber(l).reachableBy(arg).nonEmpty) && label == "true") {
          println(s"[[FP]] Condition on line $line is allow list")
        }
      }
    }

  }

  private def identifyImpossibleConds(cpg: Cpg, pair: Map[Int, String], lines: List[(String, Int)]): Unit = {
    // For each pair, check whether it is impossible
    for ((line, label) <- pair) {
      val cfgNode = cpg.cfgNode.lineNumber(line).l
      // Check the condition
      val condition = cfgNode.isCall.l
      // If only one call
      if (condition.size == 1 && condition.argument.size == 2) {
        val conditionType = condition.name.head
        val lhs           = condition.argument.argumentIndex(1).head
        val rhs           = condition.argument.argumentIndex(2).head
        val lhsValue      = resolveArgumentValue(cpg, lhs, lines)
        val rhsValue      = resolveArgumentValue(cpg, rhs, lines)
        if (lhsValue.isEmpty || rhsValue.isEmpty) {
          //println(s"At least one value is unknown, skip this")
          return
        }
        val lhsResult = lhsValue.get
        val rhsResult = rhsValue.get
        //println(s"lhs: $lhsResult, rhs: $rhsResult")
        var compResult = false
        conditionType match {
          case "<operator>.equals"       => compResult = lhsResult == rhsResult
          case "<operator>.identical"    => compResult = lhsResult == rhsResult
          case "<operator>.notEquals"    => compResult = lhsResult != rhsResult
          case "<operator>.notIdentical" => compResult = lhsResult != rhsResult
          case "<operator>.greaterThan" =>
            lhsResult match
              case i: Int if rhsResult.isInstanceOf[Int] =>
                compResult = i > rhsResult.asInstanceOf[Int]
              case _ =>
                compResult = false
          case "<operator>.greaterEqualsThan" =>
            lhsResult match
              case i: Int if rhsResult.isInstanceOf[Int] =>
                compResult = i >= rhsResult.asInstanceOf[Int]
              case _ =>
                compResult = false
          case "<operator>.lessThan" =>
            lhsResult match
              case i: Int if rhsResult.isInstanceOf[Int] =>
                compResult = i < rhsResult.asInstanceOf[Int]
              case _ =>
                compResult = false
          case "<operator>.lessEqualsThan" =>
            lhsResult match
              case i: Int if rhsResult.isInstanceOf[Int] =>
                compResult = i <= rhsResult.asInstanceOf[Int]
              case _ =>
                compResult = false
          case _ =>
        }
        if (compResult && label == "false") {
          println(s"[[FP]]Condition on line $line is impossible")
        } else if (!compResult && label == "true") {
          println(s"[[FP]]Condition on line $line is impossible")
        }
      }
    }
  }

  private def resolveArgumentValue(
    cpg: Cpg,
    argument: Expression,
    pairs: List[(String,Int)]
  ): Option[String | Int | Boolean] = {
    val lineNumbers = pairs.map(_._2)
    argument match {
      case literal: Literal =>
        // Handle literal: Return the literal value as a String or Int
        literal.code match {
          case lit if lit.startsWith("\"") || lit.startsWith("'") =>
            Some(lit.stripPrefix("\"").stripSuffix("\"")) // String literal
          case lit if lit.matches("-?\\d+") => Some(lit.toInt) // Integer literal
          case lit if lit == "true"         => Some(true)      // True literal
          case lit if lit == "false"        => Some(false)     // False literal
          case _                            => None
        }

      case identifier: Identifier =>
        // Handle identifier: Resolve its value if it's a local variable
        val localDefs = identifier.method.local.name(identifier.name).referencingIdentifiers.flatMap(_.reachingDefIn)

        localDefs
          .collectFirst { case literal: Literal =>
            literal.code match {
              case lit if lit.startsWith("\"") || lit.startsWith("'") =>
                lit.stripPrefix("\"").stripSuffix("\"") // Return String
              case lit if lit.matches("-?\\d+") => lit.toInt // Return Int
              case lit if lit == "true"         => true      // True literal
              case lit if lit == "false"        => false     // False literal

            }
          }
          .orElse {
            // If it's an argument to a function, resolve based on the function call at given line numbers
            // Find the function or method containing the identifier
            val containingFunction = identifier.method

            // Get the name of the function containing the identifier
            val methodName = containingFunction.name

            // Get the index of the argument corresponding to the identifier
            val argIndexOpt = containingFunction.parameter.name(identifier.name).headOption.map(_.order)

            argIndexOpt match {
              case Some(argIndex) =>
                // Find the calls to this method at the specified line numbers
                val callsToFunction = cpg.call.name(methodName).lineNumber(lineNumbers*).l

                // For each call, check if the argument at argIndex is a literal and return its value
                callsToFunction.flatMap { call =>
                  call.argument.order(argIndex).isLiteral.code.headOption.map(_.stripPrefix("\"").stripSuffix("\""))
                }.headOption

              case None =>
                // If there's no matching argument index, return None
                None
            }
          }

      case _ => None // For any other complex cases, return None
    }
  }
}
