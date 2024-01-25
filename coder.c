#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <clang-c/Index.h>

typedef unsigned int uint;

typedef enum CXChildVisitResult CXChildVisitResult;

///////////////////////////// PARSE ARGS /////////////////////////////

typedef struct {
    const char *header_path;
    const char *class_name;
    const char **compiler_args;
    const int compiler_args_n;
} FuzzerArgs;

// If error all FuzzerArgs null
FuzzerArgs parse_args(const int argc, const char **argv) {
    FuzzerArgs args = {0, 0, 0, argc - 3};

    if (argc < 3)
        return args;

    args.header_path = argv[1];
    args.class_name = argv[2];
    args.compiler_args = argv + 3;

    return args;
}

// Print usage and return error code
int usage(const char *program_name) {
    printf("Usage: %s <header> <class> ...args_to_compiler...\n", program_name);
    return 1;
}

// Print error and return error code
int print_error(const char *message) {
    fprintf(stderr, "%s\n", message);
    return 1;
}

///////////////////////////// SETUP CLANG /////////////////////////////

typedef struct {
    CXIndex index;
    CXTranslationUnit translation_unit;
    CXCursor root_cursor;
} ClangData;

// If error index is NULL
ClangData init_clang(const FuzzerArgs *args) {
    ClangData d = {0, 0, 0};

    d.index = clang_createIndex(0, 0);
    d.translation_unit = clang_parseTranslationUnit(
        d.index,
        args->header_path,
        args->compiler_args,
        args->compiler_args_n,
        0,
        0,
        CXTranslationUnit_None
    );

    if (!d.translation_unit) {
        clang_disposeIndex(d.index);
        d.index = 0;
        return d;
    }

    d.root_cursor = clang_getTranslationUnitCursor(d.translation_unit);
    return d;
}

void deinit_clang(ClangData d) {
    clang_disposeTranslationUnit(d.translation_unit);
    clang_disposeIndex(d.index);
}

///////////////////////////// FIND CLASS /////////////////////////////

typedef struct {
    const char *name;
    CXCursor cursor;
} ClangClassInfo;

CXChildVisitResult class_search_visitor(CXCursor cursor, CXCursor parent, CXClientData client_data) {
    if (clang_getCursorKind(cursor) == CXCursor_ClassDecl) {
        CXString current_class = clang_getCursorSpelling(cursor);

        ClangClassInfo *i = (ClangClassInfo * )client_data;
        if (strcmp(clang_getCString(current_class), i->name) == 0) {
            i->cursor = cursor;
            clang_disposeString(current_class);
            return CXChildVisit_Break;
        }

        clang_disposeString(current_class);
    }
    return CXChildVisit_Recurse;
}

// If not found then CXCursor is NULL
CXCursor find_class(ClangData d, const char *class_name) {
    ClangClassInfo i = {class_name, 0};
    clang_visitChildren(d.root_cursor, class_search_visitor, (CXClientData)&i);
    return i.cursor;
}

///////////////////////////// EXTRACT CLASS DATA /////////////////////////////

typedef struct {
    const char **arg_types;
    size_t arg_len;
} ConstructorInfo;

typedef struct {
    const char *name;
    const char **arg_types;
    size_t arg_len;
} MethodInfo;

typedef struct {
    const char *class_name;
    ConstructorInfo *constructors;
    size_t constr_len;
    MethodInfo *methods;
    size_t method_len;
} FuzgenData;

void deinit(FuzgenData *d) {
    for (size_t i = 0; i < 10; ++i) {
        for (size_t j = 0; i < d->constr_len && j < d->constructors[i].arg_len; ++j)
            free(d->constructors[i].arg_types[j]);
        free(d->constructors[i].arg_types);        
    }
    free(d->constructors);
    
    for (size_t i = 0; i < 10; ++i) {
        if (i < d->method_len)
            free(d->methods[i].name);
        for (size_t j = 0; i < d->method_len && j < d->methods[i].arg_len; ++j)
            free(d->methods[i].arg_types[j]);
        free(d->methods[i].arg_types);
    }
    free(d->methods);
}

CXChildVisitResult dump_class_visitor(CXCursor cursor, CXCursor parent, CXClientData client_data) {
    FuzgenData *d = (FuzgenData *)client_data;
    CXString s = clang_getCursorSpelling(parent);
    if (strcmp(d->class_name, clang_getCString(s)))
        return CXChildVisit_Break;
    clang_disposeString(s);

    if (clang_getCursorKind(cursor) == CXCursor_Constructor) {
        ConstructorInfo *cur = d->constructors + d->constr_len;
        d->constr_len++;

        CXType constructorType = clang_getCursorType(cursor);
        cur->arg_len = clang_getNumArgTypes(constructorType);

        for (size_t i = 0; i < cur->arg_len; ++i) {
            cur->arg_types[i] = clang_getCString(clang_getTypeSpelling(clang_getArgType(constructorType, i)));
        }
    } else if (clang_getCursorKind(cursor) == CXCursor_CXXMethod) {
        MethodInfo *cur = d->methods + d->method_len;
        d->method_len++;

        cur->name = clang_getCString(clang_getCursorSpelling(cursor));
        
        CXType methodType = clang_getCursorType(cursor);
        cur->arg_len = clang_getNumArgTypes(methodType);

        for (size_t i = 0; i < cur->arg_len; ++i) {
            cur->arg_types[i] = clang_getCString(clang_getTypeSpelling(clang_getArgType(methodType, i)));
        }
    }
    return CXChildVisit_Continue;
}

FuzgenData from_class(const char *class_name, CXCursor class_cursor) {
    FuzgenData d = {class_name, malloc(10 * sizeof(ConstructorInfo)), 0, malloc(10 * sizeof(MethodInfo)), 0};
    for (size_t i = 0; i < 10; ++i) {
        d.constructors[i].arg_types = malloc(10 * sizeof(const char *));
        d.methods[i].arg_types = malloc(10 * sizeof(const char *));
    }
    clang_visitChildren(class_cursor, dump_class_visitor, (CXClientData)&d);
    return d;
}

///////////////////////////// WRITING FUZZER /////////////////////////////

/// for debug
void print_data(FuzgenData d) {
    puts("--- FUZGEN DATA ---");
    for (size_t i = 0; i < d.constr_len; ++i) {
        puts("Contructor");
        for (size_t j = 0; j < d.constructors[i].arg_len; ++j)
            printf("%s", d.constructors[i].arg_types[j]);
        puts("");
    }
    for (size_t i = 0; i < d.method_len; ++i) {
        printf("Method %s\n", d.methods[i].name);
        for (size_t j = 0; j < d.methods[i].arg_len; ++j)
            printf("%s", d.methods[i].arg_types[j]);
        puts("");
    }
}

size_t getTypeSize(const char* typeName) {
    if (strcmp(typeName, "int") == 0) {
        return sizeof(int);
    } else if (strcmp(typeName, "char") == 0) {
        return sizeof(char);
    } else if (strcmp(typeName, "float") == 0) {
        return sizeof(float);
    } else if (strcmp(typeName, "double") == 0) {
        return sizeof(double);
    } else if (strcmp(typeName, "uint") == 0) {
        return sizeof(uint);
    }
    // Add more type mappings as needed
    
    return 0;  // Default case: type name not found
}

void sprintSizeBytes(char *s, size_t value) {
    unsigned char* bytes = (unsigned char*)&value;

    for (size_t i = 0; i < sizeof(size_t); i++) {
        sprintf(s + strlen(s), "%02x ", bytes[i]);
    }
}

void write_chain(const char *header_name, FuzgenData d, FILE *f) {
    char *resulting_chain = malloc(1000 * sizeof(char));
    resulting_chain[0] = '\0';
    char trail;

    puts("\nChoose starting constructor:");
    for (size_t i = 0; i < d.constr_len; ++i) {
        printf("%zu) %s(", i, d.class_name);
        for (size_t j = 0; j + 1 < d.constructors[i].arg_len; ++j)
            printf("%s, ", d.constructors[i].arg_types[j]);
        if (d.constructors[i].arg_len > 0)
            printf("%s", d.constructors[i].arg_types[d.constructors[i].arg_len - 1]);
        puts(")");
    }
    
    printf("\n> ");
    size_t cid;
    scanf("%zu", &cid);
    scanf("%c", &trail);
    
    if (cid >= d.constr_len) {
        puts("Error");
        free(resulting_chain);
        return;
    }

    sprintSizeBytes(resulting_chain + strlen(resulting_chain), cid);

    for (size_t i = 0; i < d.constructors[cid].arg_len; ++i) {
        size_t b = getTypeSize(d.constructors[cid].arg_types[i]);
        printf("%s (%zu bytes)> ", d.constructors[cid].arg_types[i], b);

        for (size_t j = 0; j < b; ++j) {
            size_t rb;
            scanf("%c", &rb);
            sprintf(resulting_chain + strlen(resulting_chain), "%c", rb);
        }
        scanf("%c", &trail);
    }

    size_t cmd = 0;
    while (1) {
        puts("\nChoose next method (0 to exit):");
        for (size_t i = 0; i < d.method_len; ++i) {
            printf("%zu) %s(", i + 1, d.methods[i].name);
            for (size_t j = 0; j + 1 < d.methods[i].arg_len; ++j)
                printf("%s, ", d.methods[i].arg_types[j]);
            if (d.methods[i].arg_len > 0)
                printf("%s", d.methods[i].arg_types[d.methods[i].arg_len - 1]);
            puts(")");
        }

        printf("> ");
        scanf("%zu", &cmd);
        scanf("%c", &trail);
        if (cmd == 0)
            break;
        cmd -= 1;

        sprintSizeBytes(resulting_chain + strlen(resulting_chain), cmd);

        for (size_t i = 0; i < d.methods[cmd].arg_len; ++i) {
            size_t b = getTypeSize(d.methods[cmd].arg_types[i]);
            printf("%s (%zu bytes)> ", d.methods[cmd].arg_types[i], b);

            for (size_t j = 0; j < b; ++j) {
                size_t rb;
                scanf("%c", &rb);
                sprintf(resulting_chain + strlen(resulting_chain), "%c", rb);
            }
            scanf("%c", &trail);
        }
    }

    fprintf(f, "%s", resulting_chain);

    free(resulting_chain);
}

///////////////////////////// MAIN /////////////////////////////

int main(const int argc, const char **argv) {
    const FuzzerArgs args = parse_args(argc, argv);
    if (!args.header_path)
        return usage(argv[0]);

    ClangData cdata = init_clang(&args);
    if (!cdata.index)
        return print_error("Error while initializing clang");

    CXCursor class_cursor = find_class(cdata, args.class_name);
    if (clang_Cursor_isNull(class_cursor))
        return print_error("Class not found");

    FuzgenData data = from_class(args.class_name, class_cursor);
    
    FILE *file = fopen("chain", "w");
    write_chain(args.header_path, data, file);
    fclose(file);

    deinit(&data);
    deinit_clang(cdata);
    return 0;
}
