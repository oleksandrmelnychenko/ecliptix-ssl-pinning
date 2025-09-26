
#ifndef ECLIPTIX_SERVER_API_H
#define ECLIPTIX_SERVER_API_H

#ifdef ECLIPTIX_SERVER_STATIC_DEFINE
#  define ECLIPTIX_SERVER_API
#  define ECLIPTIX_SERVER_NO_EXPORT
#else
#  ifndef ECLIPTIX_SERVER_API
#    ifdef ecliptix_server_EXPORTS
        /* We are building this library */
#      define ECLIPTIX_SERVER_API __declspec(dllexport)
#    else
        /* We are using this library */
#      define ECLIPTIX_SERVER_API __declspec(dllimport)
#    endif
#  endif

#  ifndef ECLIPTIX_SERVER_NO_EXPORT
#    define ECLIPTIX_SERVER_NO_EXPORT 
#  endif
#endif

#ifndef ECLIPTIX_SERVER_DEPRECATED
#  define ECLIPTIX_SERVER_DEPRECATED __attribute__ ((__deprecated__))
#endif

#ifndef ECLIPTIX_SERVER_DEPRECATED_EXPORT
#  define ECLIPTIX_SERVER_DEPRECATED_EXPORT ECLIPTIX_SERVER_API ECLIPTIX_SERVER_DEPRECATED
#endif

#ifndef ECLIPTIX_SERVER_DEPRECATED_NO_EXPORT
#  define ECLIPTIX_SERVER_DEPRECATED_NO_EXPORT ECLIPTIX_SERVER_NO_EXPORT ECLIPTIX_SERVER_DEPRECATED
#endif

#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef ECLIPTIX_SERVER_NO_DEPRECATED
#    define ECLIPTIX_SERVER_NO_DEPRECATED
#  endif
#endif

#endif /* ECLIPTIX_SERVER_API_H */
