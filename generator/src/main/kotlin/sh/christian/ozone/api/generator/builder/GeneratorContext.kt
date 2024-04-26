package sh.christian.ozone.api.generator.builder

import com.squareup.kotlinpoet.ClassName
import com.squareup.kotlinpoet.TypeAliasSpec
import com.squareup.kotlinpoet.TypeSpec
import org.gradle.configurationcache.extensions.capitalized
import sh.christian.ozone.api.lexicon.LexiconDocument

class GeneratorContext
private constructor(
  val document: LexiconDocument,
  val definitionName: String,
  prefixOverride: String?,
) {
  constructor(
    document: LexiconDocument,
    definitionName: String,
  ) : this(document, definitionName, null)

  val authority: String = document.id.substringBeforeLast('.')
  val procedureName: String = document.id.substringAfterLast('.').removePrefix("defs")
  val classPrefix: String = prefixOverride ?: procedureName.capitalized()

  private val enums = mutableMapOf<ClassName, MutableSet<String>>()
  private val types = mutableMapOf<ClassName, TypeSpec>()
  private val typeAliases = mutableMapOf<ClassName, TypeAliasSpec>()
  private val sealedRelationships = mutableListOf<SealedRelationship>()

  fun addEnum(
    className: ClassName,
    enumName: String,
  ) {
    enums.getOrPut(className) { mutableSetOf() } += enumName
  }

  fun addType(typeSpec: TypeSpec) {
    val typeLocation = ClassName(authority, typeSpec.name!!)
    types += typeLocation to typeSpec
  }

  fun addTypeAlias(
    typeAliasSpec: TypeAliasSpec,
  ) {
    val typeAliasLocation = ClassName(authority, typeAliasSpec.name)
    typeAliases += typeAliasLocation to typeAliasSpec
  }

  fun addSealedRelationship(
    sealedInterface: ClassName,
    childClass: ClassName,
    childClassSerialName: String,
  ) {
    sealedRelationships += SealedRelationship(
      sealedInterface = sealedInterface,
      childClass = childClass,
      childClassSerialName = childClassSerialName,
    )
  }

  fun enums(): Map<ClassName, Set<String>> {
    return enums.mapValues { it.value.toSet() }
  }

  fun types(): Set<TypeSpec> = types.values.toSet()

  fun typeAliases(): Set<TypeAliasSpec> = typeAliases.values.toSet()

  fun sealedRelationships(): List<SealedRelationship> = sealedRelationships.toList()
}
