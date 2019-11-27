package foundation

// #include <virgil/crypto/foundation/vscf_foundation_public.h>
import "C"
import "runtime"


/*
* Handle KDF algorithms that are configured with salt and iteration count.
*/
type SaltedKdfAlgInfo struct {
    cCtx *C.vscf_salted_kdf_alg_info_t /*ct10*/
}

/*
* Return hash algorithm information.
*/
func (obj *SaltedKdfAlgInfo) HashAlgInfo() (AlgInfo, error) {
    proxyResult := /*pr4*/C.vscf_salted_kdf_alg_info_hash_alg_info(obj.cCtx)

    runtime.KeepAlive(obj)

    return FoundationImplementationWrapAlgInfo(proxyResult) /* r4 */
}

/*
* Return KDF salt.
*/
func (obj *SaltedKdfAlgInfo) Salt() []byte {
    proxyResult := /*pr4*/C.vscf_salted_kdf_alg_info_salt(obj.cCtx)

    runtime.KeepAlive(obj)

    return helperExtractData(proxyResult) /* r1 */
}

/*
* Return KDF iteration count.
* Note, can be 0 if KDF does not need the iteration count.
*/
func (obj *SaltedKdfAlgInfo) IterationCount() uint32 {
    proxyResult := /*pr4*/C.vscf_salted_kdf_alg_info_iteration_count(obj.cCtx)

    runtime.KeepAlive(obj)

    return uint32(proxyResult) /* r9 */
}

/* Handle underlying C context. */
func (obj *SaltedKdfAlgInfo) ctx() *C.vscf_impl_t {
    return (*C.vscf_impl_t)(obj.cCtx)
}

func NewSaltedKdfAlgInfo() *SaltedKdfAlgInfo {
    ctx := C.vscf_salted_kdf_alg_info_new()
    obj := &SaltedKdfAlgInfo {
        cCtx: ctx,
    }
    //runtime.SetFinalizer(obj, func (o *SaltedKdfAlgInfo) {o.Delete()})
    runtime.SetFinalizer(obj, (*SaltedKdfAlgInfo).Delete)
    return obj
}

/* Acquire C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSaltedKdfAlgInfoWithCtx(ctx *C.vscf_salted_kdf_alg_info_t /*ct10*/) *SaltedKdfAlgInfo {
    obj := &SaltedKdfAlgInfo {
        cCtx: ctx,
    }
    //runtime.SetFinalizer(obj, func (o *SaltedKdfAlgInfo) {o.Delete()})
    runtime.SetFinalizer(obj, (*SaltedKdfAlgInfo).Delete)
    return obj
}

/* Acquire retained C context.
* Note. This method is used in generated code only, and SHOULD NOT be used in another way.
*/
func newSaltedKdfAlgInfoCopy(ctx *C.vscf_salted_kdf_alg_info_t /*ct10*/) *SaltedKdfAlgInfo {
    obj := &SaltedKdfAlgInfo {
        cCtx: C.vscf_salted_kdf_alg_info_shallow_copy(ctx),
    }
    //runtime.SetFinalizer(obj, func (o *SaltedKdfAlgInfo) {o.Delete()})
    runtime.SetFinalizer(obj, (*SaltedKdfAlgInfo).Delete)
    return obj
}

/*
* Release underlying C context.
*/
func (obj *SaltedKdfAlgInfo) Delete() {
    if obj == nil {
        return
    }
    runtime.SetFinalizer(obj, nil)
    obj.delete()
}

/*
* Release underlying C context.
*/
func (obj *SaltedKdfAlgInfo) delete() {
    C.vscf_salted_kdf_alg_info_delete(obj.cCtx)
}

/*
* Create algorithm info with identificator, HASH algorithm info,
* salt and iteration count.
*/
func NewSaltedKdfAlgInfoWithMembers(algId AlgId, hashAlgInfo AlgInfo, salt []byte, iterationCount uint32) *SaltedKdfAlgInfo {
    saltData := helperWrapData (salt)

    hashAlgInfoCopy := C.vscf_impl_shallow_copy((*C.vscf_impl_t)(hashAlgInfo.ctx()))

    proxyResult := /*pr4*/C.vscf_salted_kdf_alg_info_new_with_members(C.vscf_alg_id_t(algId) /*pa7*/, &hashAlgInfoCopy, saltData, (C.size_t)(iterationCount)/*pa10*/)

    runtime.KeepAlive(hashAlgInfo)

    obj := &SaltedKdfAlgInfo {
        cCtx: proxyResult,
    }
    //runtime.SetFinalizer(obj, func (o *SaltedKdfAlgInfo) {o.Delete()})
    runtime.SetFinalizer(obj, (*SaltedKdfAlgInfo).Delete)
    return obj
}

/*
* Provide algorithm identificator.
*/
func (obj *SaltedKdfAlgInfo) AlgId() AlgId {
    proxyResult := /*pr4*/C.vscf_salted_kdf_alg_info_alg_id(obj.cCtx)

    runtime.KeepAlive(obj)

    return AlgId(proxyResult) /* r8 */
}
