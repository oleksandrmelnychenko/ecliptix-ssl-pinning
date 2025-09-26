
#ifndef ECLIPTIX_CLIENT_API_H
#define ECLIPTIX_CLIENT_API_H

#ifdef ECLIPTIX_CLIENT_STATIC_DEFINE
#  define ECLIPTIX_CLIENT_API
#  define ECLIPTIX_CLIENT_NO_EXPORT
#else
#  ifndef ECLIPTIX_CLIENT_API
#    ifdef ecliptix_client_EXPORTS
        /* We are building this library */
#      define ECLIPTIX_CLIENT_API __declspec(dllexport)
#    else
        /* We are using this library */
#      define ECLIPTIX_CLIENT_API __declspec(dllimport)
#    endif
#  endif

#  ifndef ECLIPTIX_CLIENT_NO_EXPORT
#    define ECLIPTIX_CLIENT_NO_EXPORT 
#  endif
#endif

#ifndef ECLIPTIX_CLIENT_DEPRECATED
#  define ECLIPTIX_CLIENT_DEPRECATED __attribute__ ((__deprecated__))
#endif

#ifndef ECLIPTIX_CLIENT_DEPRECATED_EXPORT
#  define ECLIPTIX_CLIENT_DEPRECATED_EXPORT ECLIPTIX_CLIENT_API ECLIPTIX_CLIENT_DEPRECATED
#endif

#ifndef ECLIPTIX_CLIENT_DEPRECATED_NO_EXPORT
#  define ECLIPTIX_CLIENT_DEPRECATED_NO_EXPORT ECLIPTIX_CLIENT_NO_EXPORT ECLIPTIX_CLIENT_DEPRECATED
#endif

#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef ECLIPTIX_CLIENT_NO_DEPRECATED
#    define ECLIPTIX_CLIENT_NO_DEPRECATED
#  endif
#endif

#endif /* ECLIPTIX_CLIENT_API_H */
