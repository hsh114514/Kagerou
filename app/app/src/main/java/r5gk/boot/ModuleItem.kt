package r5gk.boot

/** One row of the module list, as printed by `ksu_modules.sh list`. */
data class ModuleItem(
    val id: String,
    val name: String,
    val version: String,
    val author: String,
    val sizeKb: Long,
    /** ok | disabled | pending | remove */
    val state: String,
    val mounted: Boolean,
    /** true when modules_update/<id> is waiting to be merged in. */
    val updatable: Boolean,
)
