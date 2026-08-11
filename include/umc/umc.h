#ifndef UMC_SDK_C_UMC_H
#define UMC_SDK_C_UMC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct umc_handle_t umc_handle_t;

typedef struct {
    int32_t code;
    char *message;
} umc_status;

typedef struct {
    uint8_t *data;
    size_t len;
} umc_bytes;

const char *umc_sdk_version(void);
umc_handle_t *umc_client_new(void);
umc_status umc_client_connect(umc_handle_t *, const char *socket, const char *client_name);
umc_status umc_client_request(umc_handle_t *, const char *service, const char *method,
                              const uint8_t *payload, size_t payload_len,
                              umc_bytes *response);
umc_status umc_client_close(umc_handle_t *);
void umc_bytes_free(umc_bytes bytes);
void umc_status_free(umc_status status);

#ifdef __cplusplus
}
#endif

#endif
