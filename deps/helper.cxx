#include <x509_crt.h>

extern "C" void* jl_crt_get_pk(mbedtls_x509_crt* pcrt){
	return &(pcrt->pk);
}

extern "C" void* jl_crt_get_sig_md(mbedtls_x509_crt* pcrt){
	return &(pcrt->sig_md);
}

extern "C" void* jl_crt_get_sig(mbedtls_x509_crt* pcrt, size_t* plen){
	*plen = pcrt->sig.len;
	return pcrt->sig.p;
}

extern "C" void* jl_crt_get_tbs(mbedtls_x509_crt* pcrt, size_t* plen){
	*plen = pcrt->tbs.len;
	return pcrt->tbs.p;
}
