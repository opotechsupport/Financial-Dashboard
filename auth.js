/* =========================================================
   RYANAIR FINANCIAL DASHBOARD
   AUTHENTICATION & USER MANAGEMENT CORE
   =========================================================

   CENTRAL RESPONSIBILITY
   ----------------------

   This file controls:

   • Authentication
   • Sessions
   • First Administrator setup
   • Master Security Key
   • User Management
   • Roles
   • Permissions
   • Profiles
   • Password management
   • User activation/deactivation
   • User archive/restore
   • User deletion
   • Audit events
   • Authentication events

   Firebase access is handled exclusively through:

       firebase.js

   UI / Modals are handled by:

       app.js
       index.html
       modal system

   =========================================================

   DATABASE STRUCTURE

   users/
       username/
           profile/
           credentials/
           permissions/
           metadata/

   system/
       security/
       settings/
       metadata/

   logs/
       logId/

   contracts/
       contractId/

   ========================================================= */


/* =========================================================
   FIREBASE CORE
========================================================= */

import {

    firebaseRef,
    firebaseGet,
    firebaseSet,
    firebaseUpdate,
    firebaseRemove,
    firebasePush,

    userRef,
    userProfileRef,
    userCredentialsRef,
    userPermissionsRef,
    userMetadataRef,

    securityRef,
    logsRef,

    DATABASE_PATHS

} from "./firebase.js";


/* =========================================================
   PATHS
========================================================= */

const PATHS = Object.freeze({

    USERS:
        DATABASE_PATHS.USERS,

    SECURITY:
        DATABASE_PATHS.SECURITY,

    LOGS:
        DATABASE_PATHS.LOGS

});


/* =========================================================
   ROLES
========================================================= */

const USER_ROLES = Object.freeze({

    ADMIN:
        "admin",

    FINANCIAL:
        "financial",

    USER:
        "user"

});


const ROLE_NAMES = Object.freeze({

    admin:
        "Administrator",

    financial:
        "Financial",

    user:
        "User"

});


/* =========================================================
   PERMISSIONS
========================================================= */

const PERMISSIONS = Object.freeze({

    /* ---------------------------------
       SYSTEM
    --------------------------------- */

    ACCESS_DASHBOARD:
        "accessDashboard",

    VIEW_SETTINGS:
        "viewSettings",

    MANAGE_SETTINGS:
        "manageSettings",

    VIEW_LOGS:
        "viewLogs",

    CLEAR_LOGS:
        "clearLogs",


    /* ---------------------------------
       USER MANAGEMENT
    --------------------------------- */

    VIEW_USERS:
        "viewUsers",

    CREATE_USERS:
        "createUsers",

    EDIT_USERS:
        "editUsers",

    DELETE_USERS:
        "deleteUsers",

    CHANGE_USER_ROLE:
        "changeUserRole",

    CHANGE_USER_STATUS:
        "changeUserStatus",

    RESET_USER_PASSWORD:
        "resetUserPassword",


    /* ---------------------------------
       PROFILE
    --------------------------------- */

    EDIT_PROFILE:
        "editProfile",

    CHANGE_PASSWORD:
        "changePassword",

    CHANGE_PROFILE_PHOTO:
        "changeProfilePhoto",


    /* ---------------------------------
       CONTRACT MANAGEMENT
    --------------------------------- */

    VIEW_CONTRACTS:
        "viewContracts",

    CREATE_CONTRACTS:
        "createContracts",

    EDIT_CONTRACTS:
        "editContracts",

    DELETE_CONTRACTS:
        "deleteContracts",

    ARCHIVE_CONTRACTS:
        "archiveContracts",

    VIEW_CONTRACT_FINANCIALS:
        "viewContractFinancials",

    EDIT_CONTRACT_FINANCIALS:
        "editContractFinancials",


    /* ---------------------------------
       CONTRACT DOCUMENTS
    --------------------------------- */

    VIEW_DOCUMENTS:
        "viewDocuments",

    UPLOAD_DOCUMENTS:
        "uploadDocuments",

    DOWNLOAD_DOCUMENTS:
        "downloadDocuments",

    DELETE_DOCUMENTS:
        "deleteDocuments",

    REPLACE_DOCUMENTS:
        "replaceDocuments",


    /* ---------------------------------
       SECURITY
    --------------------------------- */

    USE_MASTER_SECURITY_KEY:
        "useMasterSecurityKey"

});


/* =========================================================
   DEFAULT ROLE PERMISSIONS
========================================================= */

const DEFAULT_PERMISSIONS = Object.freeze({

    /* ---------------------------------
       ADMINISTRATOR
    --------------------------------- */

    admin: {

        accessDashboard:
            true,

        viewSettings:
            true,

        manageSettings:
            true,

        viewLogs:
            true,

        clearLogs:
            true,

        viewUsers:
            true,

        createUsers:
            true,

        editUsers:
            true,

        deleteUsers:
            true,

        changeUserRole:
            true,

        changeUserStatus:
            true,

        resetUserPassword:
            true,

        editProfile:
            true,

        changePassword:
            true,

        changeProfilePhoto:
            true,

        viewContracts:
            true,

        createContracts:
            true,

        editContracts:
            true,

        deleteContracts:
            true,

        archiveContracts:
            true,

        viewContractFinancials:
            true,

        editContractFinancials:
            true,

        viewDocuments:
            true,

        uploadDocuments:
            true,

        downloadDocuments:
            true,

        deleteDocuments:
            true,

        replaceDocuments:
            true,

        useMasterSecurityKey:
            true

    },


    /* ---------------------------------
       FINANCIAL
    --------------------------------- */

    financial: {

        accessDashboard:
            true,

        viewSettings:
            true,

        editProfile:
            true,

        changePassword:
            true,

        changeProfilePhoto:
            true

        /*
            Contract permissions intentionally remain
            configurable until we define the exact
            Financial role requirements.
        */

    },


    /* ---------------------------------
       USER
    --------------------------------- */

    user: {

        accessDashboard:
            true,

        editProfile:
            true,

        changePassword:
            true,

        changeProfilePhoto:
            true

    }

});


/* =========================================================
   AUTH EVENTS
========================================================= */

const AUTH_EVENTS = Object.freeze({

    READY:
        "financial-auth-ready",

    LOGIN:
        "financial-auth-login",

    LOGOUT:
        "financial-auth-logout",

    FIRST_INSTALLATION:
        "financial-auth-first-installation",

    SESSION_EXPIRED:
        "financial-auth-session-expired",

    ACCESS_DENIED:
        "financial-auth-access-denied",

    USER_CREATED:
        "financial-auth-user-created",

    USER_UPDATED:
        "financial-auth-user-updated",

    USER_DELETED:
        "financial-auth-user-deleted"

});


/* =========================================================
   SESSION CONFIGURATION
========================================================= */

const SESSION_STORAGE_KEY =
    "RYANAIR_FINANCIAL_SESSION";


const SESSION_VERSION =
    1;


/*
   Maximum inactive/session lifetime.

   This is client-side session management.
   Firebase Security Rules remain the actual
   database security layer.
*/

const SESSION_DURATION =
    8 * 60 * 60 * 1000;


/* =========================================================
   INTERNAL STATE
========================================================= */

let CURRENT_USER =
    null;


let CURRENT_SESSION =
    null;


let AUTH_READY =
    false;


let AUTH_ERROR =
    null;


let FIRST_INSTALLATION =
    false;


let USERS_CACHE =
    [];


let LAST_ACTIVITY_UPDATE =
    0;


/* =========================================================
   EVENT EMITTER
========================================================= */

function emitAuthEvent(

    eventName,

    detail = {}

) {

    try {

        window.dispatchEvent(

            new CustomEvent(

                eventName,

                {

                    detail: {

                        ...detail,

                        timestamp:
                            Date.now()

                    }

                }

            )

        );

    }
    catch(error) {

        console.warn(

            "AUTH — Event dispatch failed:",

            error

        );

    }

}


/* =========================================================
   USERNAME NORMALISATION
========================================================= */

function normalizeUsername(
    username
) {

    return String(
        username || ""
    )

        .trim()

        .toLowerCase()

        .replace(
            /\s+/g,
            ""
        );

}


/* =========================================================
   ROLE NORMALISATION
========================================================= */

function normalizeRole(
    role
) {

    const normalized =
        String(
            role || ""
        )
            .trim()
            .toLowerCase();


    if(
        normalized ===
        USER_ROLES.ADMIN
    ) {

        return USER_ROLES.ADMIN;

    }


    if(
        normalized ===
        USER_ROLES.FINANCIAL
    ) {

        return USER_ROLES.FINANCIAL;

    }


    return USER_ROLES.USER;

}


/* =========================================================
   ROLE DISPLAY NAME
========================================================= */

function getRoleName(
    role
) {

    const normalizedRole =
        normalizeRole(
            role
        );


    return (

        ROLE_NAMES[
            normalizedRole
        ] ||

        "User"

    );

}


/* =========================================================
   USERNAME VALIDATION
========================================================= */

function validateUsername(
    username
) {

    const value =
        normalizeUsername(
            username
        );


    return {

        valid:
            /^[a-z0-9_-]{3,32}$/
                .test(
                    value
                ),

        value:
            value

    };

}


/* =========================================================
   PASSWORD VALIDATION
========================================================= */

function validatePassword(
    password
) {

    const value =
        String(
            password || ""
        );


    return {

        valid:
            value.length >= 6,

        length:
            value.length,

        hasMinimumLength:
            value.length >= 6,

        hasNumber:
            /\d/.test(
                value
            ),

        hasLetter:
            /[A-Za-z]/.test(
                value
            )

    };

}


/* =========================================================
   RANDOM SALT
========================================================= */

function generateSalt(
    length = 32
) {

    const characters =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";


    const values =
        new Uint32Array(
            length
        );


    crypto.getRandomValues(
        values
    );


    let result =
        "";


    values.forEach(

        value => {

            result +=
                characters[
                    value %
                    characters.length
                ];

        }

    );


    return result;

}


/* =========================================================
   MASTER SECURITY KEY GENERATOR
========================================================= */

function generateMasterKey() {

    const characters =
        "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*";


    const values =
        new Uint32Array(
            24
        );


    crypto.getRandomValues(
        values
    );


    let key =
        "";


    values.forEach(

        value => {

            key +=
                characters[
                    value %
                    characters.length
                ];

        }

    );


    return key;

}


/* =========================================================
   HASH
========================================================= */

async function hashValue(

    value,

    salt

) {

    const encoder =
        new TextEncoder();


    const data =
        encoder.encode(

            String(
                value
            ) +

            String(
                salt
            )

        );


    const buffer =
        await crypto.subtle.digest(

            "SHA-256",

            data

        );


    return Array
        .from(
            new Uint8Array(
                buffer
            )
        )

        .map(

            byte =>

                byte
                    .toString(16)
                    .padStart(
                        2,
                        "0"
                    )

        )

        .join("");

}


/* =========================================================
   PASSWORD HASH
========================================================= */

async function hashPassword(

    password,

    salt

) {

    return hashValue(
        password,
        salt
    );

}


/* =========================================================
   CLONE OBJECT
========================================================= */

function cloneObject(
    object
) {

    try {

        return JSON.parse(
            JSON.stringify(
                object
            )
        );

    }
    catch {

        return {};

    }

}


/* =========================================================
   CREATE PERMISSIONS
========================================================= */

function createPermissions(

    role,

    customPermissions = {}

) {

    const normalizedRole =
        normalizeRole(
            role
        );


    const defaults =
        DEFAULT_PERMISSIONS[
            normalizedRole
        ] || {};


    return {

        ...defaults,

        ...customPermissions

    };

}


/* =========================================================
   USER OBJECT NORMALISATION
========================================================= */

function normalizeUserObject(

    username,

    user

) {

    const profile =
        user?.profile || {};


    const credentials =
        user?.credentials || {};


    const metadata =
        user?.metadata || {};


    const role =
        normalizeRole(
            profile.role
        );


    return {

        id:
            normalizeUsername(
                username
            ),


        profile: {

            username:
                profile.username ||
                normalizeUsername(
                    username
                ),

            fullName:
                profile.fullName ||
                "User",

            role:
                role,

            active:
                profile.active !== false,

            archived:
                profile.archived === true,

            photo:
                profile.photo ||
                null

        },


        credentials: {

            salt:
                credentials.salt ||
                null,

            passwordHash:
                credentials.passwordHash ||
                null

        },


        permissions:

            createPermissions(

                role,

                user?.permissions || {}

            ),


        metadata: {

            ...metadata

        }

    };

}


/* =========================================================
   SANITISE USER FOR UI
========================================================= */

/*
   IMPORTANT:

   credentials are NEVER returned to the interface.

   User Management only receives safe information.
*/

function sanitizeUserForUI(
    user
) {

    if(
        !user
    ) {

        return null;

    }


    return {

        id:
            user.id,


        profile: {

            username:
                user.profile?.username ||
                "",

            fullName:
                user.profile?.fullName ||
                "",

            role:
                user.profile?.role ||
                USER_ROLES.USER,

            roleName:
                getRoleName(
                    user.profile?.role
                ),

            active:
                user.profile?.active !== false,

            archived:
                user.profile?.archived === true,

            photo:
                user.profile?.photo ||
                null

        },


        permissions:
            cloneObject(
                user.permissions || {}
            ),


        metadata: {

            createdAt:
                user.metadata?.createdAt ||
                null,

            createdBy:
                user.metadata?.createdBy ||
                null,

            updatedAt:
                user.metadata?.updatedAt ||
                null,

            lastLogin:
                user.metadata?.lastLogin ||
                null,

            passwordResetAt:
                user.metadata?.passwordResetAt ||
                null,

            passwordResetBy:
                user.metadata?.passwordResetBy ||
                null,

            usernameChangedAt:
                user.metadata?.usernameChangedAt ||
                null,

            archivedAt:
                user.metadata?.archivedAt ||
                null,

            archivedBy:
                user.metadata?.archivedBy ||
                null

        }

    };

}


/* =========================================================
   USER REFERENCE
========================================================= */

function getUserReference(
    username
) {

    return userRef(

        normalizeUsername(
            username
        )

    );

}


/* =========================================================
   GET USER
========================================================= */

async function getUserByUsername(
    username
) {

    const normalizedUsername =
        normalizeUsername(
            username
        );


    if(
        !normalizedUsername
    ) {

        return null;

    }


    const snapshot =
        await firebaseGet(

            getUserReference(
                normalizedUsername
            )

        );


    if(
        !snapshot.exists()
    ) {

        return null;

    }


    return normalizeUserObject(

        normalizedUsername,

        snapshot.val() || {}

    );

}


/* =========================================================
   USER EXISTS
========================================================= */

async function userExists(
    username
) {

    return (

        await getUserByUsername(
            username
        )

    ) !== null;

}


/* =========================================================
   CHECK IF DATABASE HAS USERS
========================================================= */

async function hasAnyUsers() {

    const snapshot =
        await firebaseGet(

            firebaseRef(
                PATHS.USERS
            )

        );


    return snapshot.exists();

}


/* =========================================================
   BUILD USER OBJECT
========================================================= */

function buildUserObject({

    username,

    fullName,

    role,

    salt,

    passwordHash,

    photo =
        null,

    createdBy =
        "SYSTEM",

    customPermissions =
        {}

}) {

    const normalizedUsername =
        normalizeUsername(
            username
        );


    const normalizedRole =
        normalizeRole(
            role
        );


    return {

        profile: {

            username:
                normalizedUsername,

            fullName:
                String(
                    fullName || ""
                ).trim(),

            role:
                normalizedRole,

            active:
                true,

            archived:
                false,

            photo:
                photo || null

        },


        credentials: {

            salt:
                salt,

            passwordHash:
                passwordHash

        },


        permissions:

            createPermissions(

                normalizedRole,

                customPermissions

            ),


        metadata: {

            createdAt:
                Date.now(),

            createdBy:
                createdBy,

            updatedAt:
                Date.now(),

            lastLogin:
                null

        }

    };

}


/* =========================================================
   CREATE USER
========================================================= */

async function createUser({

    fullName,

    username,

    password,

    role =
        USER_ROLES.USER,

    photo =
        null,

    createdBy =
        "SELF_REGISTRATION",

    customPermissions =
        {}

}) {

    const usernameValidation =
        validateUsername(
            username
        );


    if(
        !usernameValidation.valid
    ) {

        throw new Error(
            "INVALID_USERNAME"
        );

    }


    const passwordValidation =
        validatePassword(
            password
        );


    if(
        !passwordValidation.valid
    ) {

        throw new Error(
            "INVALID_PASSWORD"
        );

    }


    const cleanFullName =
        String(
            fullName || ""
        ).trim();


    if(
        !cleanFullName
    ) {

        throw new Error(
            "INVALID_FULL_NAME"
        );

    }


    const normalizedUsername =
        usernameValidation.value;


    if(
        await userExists(
            normalizedUsername
        )
    ) {

        throw new Error(
            "USERNAME_ALREADY_EXISTS"
        );

    }


    const normalizedRole =
        normalizeRole(
            role
        );


    /*
       Only administrators may create another
       administrator.
    */

    if(
        normalizedRole ===
        USER_ROLES.ADMIN &&
        CURRENT_USER &&
        !isAdmin()
    ) {

        throw new Error(
            "ACCESS_DENIED"
        );

    }


    const salt =
        generateSalt();


    const passwordHash =
        await hashPassword(

            password,

            salt

        );


    const user =
        buildUserObject({

            username:
                normalizedUsername,

            fullName:
                cleanFullName,

            role:
                normalizedRole,

            salt:
                salt,

            passwordHash:
                passwordHash,

            photo:
                photo,

            createdBy:
                createdBy,

            customPermissions:
                customPermissions

        });


    await firebaseSet(

        getUserReference(
            normalizedUsername
        ),

        user

    );


    invalidateUsersCache();


    const safeUser =
        sanitizeUserForUI(

            normalizeUserObject(

                normalizedUsername,

                user

            )

        );


    await writeAuditLog(

        "USER_CREATED",

        "USER_MANAGEMENT",

        {

            targetUser:
                normalizedUsername,

            role:
                normalizedRole

        }

    );


    emitAuthEvent(

        AUTH_EVENTS.USER_CREATED,

        {

            user:
                safeUser

        }

    );


    return safeUser;

}


/* =========================================================
   CREATE FIRST ADMINISTRATOR
========================================================= */

async function createFirstAdministrator({

    fullName,

    username,

    password,

    masterKey,

    photo =
        null

}) {

    /*
       Absolute first-installation protection.
    */

    if(
        await hasAnyUsers()
    ) {

        throw new Error(
            "ADMINISTRATOR_ALREADY_EXISTS"
        );

    }


    if(
        !masterKey ||
        String(
            masterKey
        ).length < 8
    ) {

        throw new Error(
            "INVALID_MASTER_KEY"
        );

    }


    /*
       Create Administrator directly.

       We do not call createUser() because first
       installation is a special controlled flow.
    */

    const usernameValidation =
        validateUsername(
            username
        );


    if(
        !usernameValidation.valid
    ) {

        throw new Error(
            "INVALID_USERNAME"
        );

    }


    const passwordValidation =
        validatePassword(
            password
        );


    if(
        !passwordValidation.valid
    ) {

        throw new Error(
            "INVALID_PASSWORD"
        );

    }


    if(
        !String(
            fullName || ""
        ).trim()
    ) {

        throw new Error(
            "INVALID_FULL_NAME"
        );

    }


    const normalizedUsername =
        usernameValidation.value;


    const passwordSalt =
        generateSalt();


    const passwordHash =
        await hashPassword(

            password,

            passwordSalt

        );


    const admin =
        buildUserObject({

            username:
                normalizedUsername,

            fullName:
                fullName,

            role:
                USER_ROLES.ADMIN,

            salt:
                passwordSalt,

            passwordHash:
                passwordHash,

            photo:
                photo,

            createdBy:
                "SYSTEM"

        });


    /*
       Master Security Key.
    */

    const masterKeySalt =
        generateSalt();


    const masterKeyHash =
        await hashValue(

            masterKey,

            masterKeySalt

        );


    /*
       Write administrator.
    */

    await firebaseSet(

        getUserReference(
            normalizedUsername
        ),

        admin

    );


    /*
       Write security configuration.
    */

    await firebaseSet(

        securityRef(),

        {

            masterKeySalt:
                masterKeySalt,

            masterKeyHash:
                masterKeyHash,

            createdAt:
                Date.now(),

            createdBy:
                normalizedUsername

        }

    );


    /*
       Start authenticated session.
    */

    CURRENT_USER =
        normalizeUserObject(

            normalizedUsername,

            admin

        );


    CURRENT_SESSION =
        createSession(
            normalizedUsername
        );


    saveSession(
        CURRENT_SESSION
    );


    FIRST_INSTALLATION =
        false;


    invalidateUsersCache();


    await writeAuditLog(

        "CREATE_FIRST_ADMIN",

        "AUTH",

        {

            username:
                normalizedUsername

        }

    );


    emitAuthEvent(

        AUTH_EVENTS.LOGIN,

        {

            user:
                sanitizeUserForUI(
                    CURRENT_USER
                ),

            firstAdministrator:
                true

        }

    );


    return sanitizeUserForUI(
        CURRENT_USER
    );

}


/* =========================================================
   LOGIN
========================================================= */

async function loginUser(

    username,

    password

) {

    const normalizedUsername =
        normalizeUsername(
            username
        );


    if(
        !normalizedUsername ||
        !password
    ) {

        return {

            success:
                false,

            error:
                "MISSING_CREDENTIALS"

        };

    }


    try {

        const user =
            await getUserByUsername(
                normalizedUsername
            );


        if(
            !user
        ) {

            await writeAuditLog(

                "LOGIN_FAILED",

                "AUTH",

                {

                    username:
                        normalizedUsername

                }

            );


            return {

                success:
                    false,

                error:
                    "INVALID_CREDENTIALS"

            };

        }


        if(
            user.profile.archived
        ) {

            return {

                success:
                    false,

                error:
                    "ACCOUNT_ARCHIVED"

            };

        }


        if(
            user.profile.active === false
        ) {

            return {

                success:
                    false,

                error:
                    "ACCOUNT_DISABLED"

            };

        }


        if(
            !user.credentials.salt ||
            !user.credentials.passwordHash
        ) {

            return {

                success:
                    false,

                error:
                    "ACCOUNT_NOT_CONFIGURED"

            };

        }


        const calculatedHash =
            await hashPassword(

                password,

                user.credentials.salt

            );


        if(
            calculatedHash !==
            user.credentials.passwordHash
        ) {

            await writeAuditLog(

                "LOGIN_FAILED",

                "AUTH",

                {

                    username:
                        normalizedUsername

                }

            );


            return {

                success:
                    false,

                error:
                    "INVALID_CREDENTIALS"

            };

        }


        CURRENT_USER =
            user;


        CURRENT_SESSION =
            createSession(
                normalizedUsername
            );


        saveSession(
            CURRENT_SESSION
        );


       /*
   Update last login.
*/

const loginTimestamp =
    Date.now();


try {

    await firebaseUpdate(

        userMetadataRef(
            normalizedUsername
        ),

        {

            lastLogin:
                loginTimestamp,

            updatedAt:
                loginTimestamp

        }

    );


    /*
       Keep CURRENT_USER synchronized with
       the Firebase value immediately.

       This prevents the UI from showing
       stale "First Login" information after
       a successful login.
    */

    CURRENT_USER =
        CURRENT_USER ||
        user;


    CURRENT_USER.metadata =
        CURRENT_USER.metadata ||
        {};


    CURRENT_USER.metadata.lastLogin =
        loginTimestamp;


    CURRENT_USER.metadata.updatedAt =
        loginTimestamp;

}
catch(error) {

    console.warn(

        "AUTH — Could not update last login:",

        error

    );

}

        await writeAuditLog(

            "LOGIN",

            "AUTH",

            {

                username:
                    normalizedUsername,

                role:
                    user.profile.role

            }

        );


        emitAuthEvent(

            AUTH_EVENTS.LOGIN,

            {

                user:
                    sanitizeUserForUI(
                        CURRENT_USER
                    )

            }

        );


        return {

            success:
                true,

            user:
                sanitizeUserForUI(
                    CURRENT_USER
                )

        };

    }
    catch(error) {

        console.error(

            "AUTH — Login failed:",

            error

        );


        AUTH_ERROR =
            error;


        return {

            success:
                false,

            error:
                "LOGIN_ERROR",

            details:
                error

        };

    }

}


/* =========================================================
   LOGOUT
========================================================= */

async function logoutUser() {

    const username =
        getCurrentUsername();


    if(
        username
    ) {

        await writeAuditLog(

            "LOGOUT",

            "AUTH",

            {

                username:
                    username

            }

        );

    }


    CURRENT_USER =
        null;


    CURRENT_SESSION =
        null;


    clearSession();


    emitAuthEvent(

        AUTH_EVENTS.LOGOUT

    );


    return true;

}


/* =========================================================
   SESSION CREATION
========================================================= */

function createSession(
    username
) {

    return {

        version:
            SESSION_VERSION,

        username:
            normalizeUsername(
                username
            ),

        createdAt:
            Date.now(),

        lastActivity:
            Date.now(),

        expiresAt:
            Date.now() +
            SESSION_DURATION

    };

}


/* =========================================================
   SAVE SESSION
========================================================= */

function saveSession(
    session
) {

    if(
        !session
    ) {

        return false;

    }


    try {

        localStorage.setItem(

            SESSION_STORAGE_KEY,

            JSON.stringify(
                session
            )

        );


        return true;

    }
    catch(error) {

        console.warn(

            "AUTH — Could not save session:",

            error

        );


        return false;

    }

}


/* =========================================================
   GET SAVED SESSION
========================================================= */

function getSavedSession() {

    try {

        const stored =
            localStorage.getItem(
                SESSION_STORAGE_KEY
            );


        if(
            !stored
        ) {

            return null;

        }


        const session =
            JSON.parse(
                stored
            );


        if(
            !session ||
            !session.username
        ) {

            return null;

        }


        return session;

    }
    catch {

        return null;

    }

}


/* =========================================================
   CLEAR SESSION
========================================================= */

function clearSession() {

    try {

        localStorage.removeItem(
            SESSION_STORAGE_KEY
        );

    }
    catch {

        /* Ignore */

    }


    CURRENT_SESSION =
        null;

}


/* =========================================================
   SESSION VALIDATION
========================================================= */

function isSessionValid(
    session
) {

    if(
        !session ||
        !session.username
    ) {

        return false;

    }


    if(
        session.version !==
        SESSION_VERSION
    ) {

        return false;

    }


    if(
        !session.expiresAt
    ) {

        return false;

    }


    if(
        Date.now() >
        session.expiresAt
    ) {

        return false;

    }


    return true;

}


/* =========================================================
   REFRESH SESSION
========================================================= */

function refreshSession() {

    if(
        !CURRENT_SESSION
    ) {

        return false;

    }


    CURRENT_SESSION.lastActivity =
        Date.now();


    CURRENT_SESSION.expiresAt =
        Date.now() +
        SESSION_DURATION;


    saveSession(
        CURRENT_SESSION
    );


    return true;

}


/* =========================================================
   RESTORE SESSION
========================================================= */

async function restoreSession() {

    const session =
        getSavedSession();


    if(
        !isSessionValid(
            session
        )
    ) {

        clearSession();


        return {

            restored:
                false,

            reason:
                "SESSION_EXPIRED"

        };

    }


    try {

        const user =
            await getUserByUsername(

                session.username

            );


        if(
            !user
        ) {

            clearSession();


            return {

                restored:
                    false,

                reason:
                    "USER_NOT_FOUND"

            };

        }


        if(
            user.profile.active === false ||
            user.profile.archived === true
        ) {

            clearSession();


            return {

                restored:
                    false,

                reason:
                    "ACCOUNT_DISABLED"

            };

        }


        CURRENT_USER =
            user;


        CURRENT_SESSION =
            session;


        refreshSession();


        return {

            restored:
                true,

            user:
                sanitizeUserForUI(
                    CURRENT_USER
                )

        };

    }
    catch(error) {

        console.error(

            "AUTH — Session restore failed:",

            error

        );


        clearSession();


        return {

            restored:
                false,

            reason:
                "RESTORE_ERROR"

        };

    }

}


/* =========================================================
   INITIALISE AUTHENTICATION
========================================================= */

async function initialiseAuthentication() {

    AUTH_READY =
        false;


    AUTH_ERROR =
        null;


    FIRST_INSTALLATION =
        false;


    try {

        const usersExist =
            await hasAnyUsers();


        /*
           Completely empty Firebase.
        */

        if(
            !usersExist
        ) {

            FIRST_INSTALLATION =
                true;


            AUTH_READY =
                true;


            emitAuthEvent(

                AUTH_EVENTS.FIRST_INSTALLATION

            );


            emitAuthEvent(

                AUTH_EVENTS.READY,

                {

                    firstInstallation:
                        true,

                    authenticated:
                        false,

                    user:
                        null

                }

            );


            return {

                firstInstallation:
                    true,

                authenticated:
                    false,

                user:
                    null

            };

        }


        /*
           Existing installation.
        */

        const restored =
            await restoreSession();


        AUTH_READY =
            true;


        emitAuthEvent(

            AUTH_EVENTS.READY,

            {

                firstInstallation:
                    false,

                authenticated:
                    restored.restored,

                user:
                    CURRENT_USER
                        ? sanitizeUserForUI(
                            CURRENT_USER
                        )
                        : null

            }

        );


        if(
            restored.reason ===
            "SESSION_EXPIRED"
        ) {

            emitAuthEvent(

                AUTH_EVENTS.SESSION_EXPIRED

            );

        }


        return {

            firstInstallation:
                false,

            authenticated:
                restored.restored,

            user:
                restored.restored
                    ? sanitizeUserForUI(
                        CURRENT_USER
                    )
                    : null

        };

    }
    catch(error) {

        console.error(

            "AUTH — Initialisation failed:",

            error

        );


        AUTH_ERROR =
            error;


        AUTH_READY =
            true;


        return {

            firstInstallation:
                false,

            authenticated:
                false,

            user:
                null,

            error:
                error

        };

    }

}


/* =========================================================
   ADMINISTRATOR COUNT
========================================================= */

async function getAdministratorCount() {

    const users =
        await loadAllUsers(
            true
        );


    return users.filter(

        user =>

            user.profile?.role ===
            USER_ROLES.ADMIN

    ).length;

}


/* =========================================================
   LOAD ALL USERS
========================================================= */

async function loadAllUsers(

    forceRefresh =
        false

) {

    if(
        !forceRefresh &&
        USERS_CACHE.length > 0
    ) {

        return USERS_CACHE.map(
            sanitizeUserForUI
        );

    }


    const snapshot =
        await firebaseGet(

            firebaseRef(
                PATHS.USERS
            )

        );


    USERS_CACHE =
        [];


    if(
        !snapshot.exists()
    ) {

        return [];

    }


    snapshot.forEach(

        child => {

            USERS_CACHE.push(

                normalizeUserObject(

                    child.key,

                    child.val() || {}

                )

            );

        }

    );


    USERS_CACHE.sort(

        (a, b) =>

            String(
                a.profile.fullName
            )
                .localeCompare(

                    String(
                        b.profile.fullName
                    )

                )

    );


    return USERS_CACHE.map(
        sanitizeUserForUI
    );

}


/* =========================================================
   INVALIDATE CACHE
========================================================= */

function invalidateUsersCache() {

    USERS_CACHE =
        [];

}


/* =========================================================
   SEARCH USERS
========================================================= */

async function searchUsers(

    searchTerm =
        "",

    options =
        {}

) {

    const users =
        await loadAllUsers();


    const term =
        String(
            searchTerm || ""
        )
            .trim()
            .toLowerCase();


    let filtered =
        users;


    if(
        term
    ) {

        filtered =
            users.filter(

                user => {

                    const username =
                        String(
                            user.profile?.username ||
                            ""
                        ).toLowerCase();


                    const fullName =
                        String(
                            user.profile?.fullName ||
                            ""
                        ).toLowerCase();


                    const role =
                        String(
                            user.profile?.role ||
                            ""
                        ).toLowerCase();


                    return (

                        username.includes(
                            term
                        ) ||

                        fullName.includes(
                            term
                        ) ||

                        role.includes(
                            term
                        )

                    );

                }

            );

    }


    if(
        options.role
    ) {

        filtered =
            filtered.filter(

                user =>

                    user.profile?.role ===
                    normalizeRole(
                        options.role
                    )

            );

    }


    if(
        options.active !==
        undefined
    ) {

        filtered =
            filtered.filter(

                user =>

                    user.profile?.active ===
                    Boolean(
                        options.active
                    )

            );

    }


    if(
        options.archived !==
        undefined
    ) {

        filtered =
            filtered.filter(

                user =>

                    user.profile?.archived ===
                    Boolean(
                        options.archived
                    )

            );

    }


    return filtered;

}


/* =========================================================
   UPDATE CURRENT PROFILE
========================================================= */

async function updateCurrentUserProfile({

    fullName,

    photo

}) {

    if(
        !CURRENT_USER
    ) {

        throw new Error(
            "NOT_AUTHENTICATED"
        );

    }


    const username =
        getCurrentUsername();


    const updates = {};


    if(
        fullName !==
        undefined
    ) {

        const cleanName =
            String(
                fullName
            ).trim();


        if(
            !cleanName
        ) {

            throw new Error(
                "INVALID_FULL_NAME"
            );

        }


        updates[
            "profile/fullName"
        ] =
            cleanName;

    }


    if(
        photo !==
        undefined
    ) {

        updates[
            "profile/photo"
        ] =
            photo;

    }


    updates[
        "metadata/updatedAt"
    ] =
        Date.now();


    await firebaseUpdate(

        getUserReference(
            username
        ),

        updates

    );


    CURRENT_USER =
        await getUserByUsername(
            username
        );


    emitAuthEvent(

        AUTH_EVENTS.USER_UPDATED,

        {

            user:
                sanitizeUserForUI(
                    CURRENT_USER
                )

        }

    );


    await writeAuditLog(

        "PROFILE_UPDATED",

        "PROFILE",

        {

            username:
                username

        }

    );


    return sanitizeUserForUI(
        CURRENT_USER
    );

}


/* =========================================================
   CHANGE OWN PASSWORD
========================================================= */

async function changeOwnPassword({

    currentPassword,

    newPassword

}) {

    if(
        !CURRENT_USER
    ) {

        throw new Error(
            "NOT_AUTHENTICATED"
        );

    }


    const username =
        getCurrentUsername();


    const user =
        await getUserByUsername(
            username
        );


    if(
        !user
    ) {

        throw new Error(
            "USER_NOT_FOUND"
        );

    }


    const currentHash =
        await hashPassword(

            currentPassword,

            user.credentials.salt

        );


    if(
        currentHash !==
        user.credentials.passwordHash
    ) {

        throw new Error(
            "CURRENT_PASSWORD_INVALID"
        );

    }


    const validation =
        validatePassword(
            newPassword
        );


    if(
        !validation.valid
    ) {

        throw new Error(
            "INVALID_PASSWORD"
        );

    }


    const newSalt =
        generateSalt();


    const newHash =
        await hashPassword(

            newPassword,

            newSalt

        );


    await firebaseUpdate(

        userCredentialsRef(
            username
        ),

        {

            salt:
                newSalt,

            passwordHash:
                newHash

        }

    );


    await firebaseUpdate(

        userMetadataRef(
            username
        ),

        {

            updatedAt:
                Date.now(),

            passwordChangedAt:
                Date.now()

        }

    );


    await writeAuditLog(

        "PASSWORD_CHANGED",

        "SECURITY",

        {

            username:
                username

        }

    );


    return true;

}


/* =========================================================
   ADMIN RESET PASSWORD
========================================================= */

async function adminResetUserPassword({

    username,

    newPassword,

    masterKey

}) {

    if(
        !isAdmin()
    ) {

        throw new Error(
            "ACCESS_DENIED"
        );

    }


    if(
        !hasPermission(
            PERMISSIONS.RESET_USER_PASSWORD
        )
    ) {

        throw new Error(
            "ACCESS_DENIED"
        );

    }


    if(
        !await verifyMasterSecurityKey(
            masterKey
        )
    ) {

        throw new Error(
            "INVALID_MASTER_KEY"
        );

    }


    const normalizedUsername =
        normalizeUsername(
            username
        );


    const user =
        await getUserByUsername(
            normalizedUsername
        );


    if(
        !user
    ) {

        throw new Error(
            "USER_NOT_FOUND"
        );

    }


    const validation =
        validatePassword(
            newPassword
        );


    if(
        !validation.valid
    ) {

        throw new Error(
            "INVALID_PASSWORD"
        );

    }


    const salt =
        generateSalt();


    const passwordHash =
        await hashPassword(

            newPassword,

            salt

        );


    await firebaseUpdate(

        userCredentialsRef(
            normalizedUsername
        ),

        {

            salt:
                salt,

            passwordHash:
                passwordHash

        }

    );


    await firebaseUpdate(

        userMetadataRef(
            normalizedUsername
        ),

        {

            updatedAt:
                Date.now(),

            passwordResetAt:
                Date.now(),

            passwordResetBy:
                getCurrentUsername()

        }

    );


    await writeAuditLog(

        "ADMIN_PASSWORD_RESET",

        "USER_MANAGEMENT",

        {

            targetUser:
                normalizedUsername

        }

    );


    return true;

}


/* =========================================================
   VERIFY MASTER SECURITY KEY
========================================================= */

async function verifyMasterSecurityKey(
    masterKey
) {

    if(
        !masterKey
    ) {

        return false;

    }


    try {

        const snapshot =
            await firebaseGet(

                securityRef()

            );


        if(
            !snapshot.exists()
        ) {

            return false;

        }


        const security =
            snapshot.val() || {};


        if(
            !security.masterKeySalt ||
            !security.masterKeyHash
        ) {

            return false;

        }


        const calculatedHash =
            await hashValue(

                masterKey,

                security.masterKeySalt

            );


        const valid =
            calculatedHash ===
            security.masterKeyHash;


        await writeAuditLog(

            valid
                ? "MASTER_KEY_VERIFIED"
                : "MASTER_KEY_FAILED",

            "SECURITY",

            {

                username:
                    getCurrentUsername()

            }

        );


        return valid;

    }
    catch(error) {

        console.error(

            "AUTH — Master key verification failed:",

            error

        );


        return false;

    }

}


/* =========================================================
   ADMIN UPDATE USER
========================================================= */

async function adminUpdateUser(

    username,

    updates = {}

) {

    if(
        !isAdmin()
    ) {

        throw new Error(
            "ACCESS_DENIED"
        );

    }


    if(
        !hasPermission(
            PERMISSIONS.EDIT_USERS
        )
    ) {

        throw new Error(
            "ACCESS_DENIED"
        );

    }


    const normalizedUsername =
        normalizeUsername(
            username
        );


    const user =
        await getUserByUsername(
            normalizedUsername
        );


    if(
        !user
    ) {

        throw new Error(
            "USER_NOT_FOUND"
        );

    }


    const firebaseUpdates = {};


    if(
        updates.fullName !==
        undefined
    ) {

        const fullName =
            String(
                updates.fullName
            ).trim();


        if(
            !fullName
        ) {

            throw new Error(
                "INVALID_FULL_NAME"
            );

        }


        firebaseUpdates[
            "profile/fullName"
        ] =
            fullName;

    }


    if(
        updates.photo !==
        undefined
    ) {

        firebaseUpdates[
            "profile/photo"
        ] =
            updates.photo;

    }


    if(
        updates.active !==
        undefined
    ) {

        if(
            normalizedUsername ===
            getCurrentUsername() &&
            !updates.active
        ) {

            throw new Error(
                "CANNOT_DISABLE_CURRENT_USER"
            );

        }


        firebaseUpdates[
            "profile/active"
        ] =
            Boolean(
                updates.active
            );

    }


    if(
        updates.archived !==
        undefined
    ) {

        firebaseUpdates[
            "profile/archived"
        ] =
            Boolean(
                updates.archived
            );

    }


    if(
        updates.role !==
        undefined
    ) {

        const newRole =
            normalizeRole(
                updates.role
            );


        /*
           If changing the final administrator
           to another role, block it.
        */

        if(
            user.profile.role ===
            USER_ROLES.ADMIN &&
            newRole !==
            USER_ROLES.ADMIN
        ) {

            const adminCount =
                await getAdministratorCount();


            if(
                adminCount <= 1
            ) {

                throw new Error(
                    "CANNOT_REMOVE_LAST_ADMIN_ROLE"
                );

            }

        }


        firebaseUpdates[
            "profile/role"
        ] =
            newRole;


        firebaseUpdates[
            "permissions"
        ] =
            createPermissions(

                newRole,

                updates.permissions || {}

            );

    }


    if(
        updates.permissions !==
        undefined &&
        updates.role ===
        undefined
    ) {

        firebaseUpdates[
            "permissions"
        ] =
            updates.permissions;

    }


    firebaseUpdates[
        "metadata/updatedAt"
    ] =
        Date.now();


    await firebaseUpdate(

        getUserReference(
            normalizedUsername
        ),

        firebaseUpdates

    );


    invalidateUsersCache();


    const updatedUser =
        await getUserByUsername(
            normalizedUsername
        );


    if(
        getCurrentUsername() ===
        normalizedUsername
    ) {

        CURRENT_USER =
            updatedUser;

    }


    await writeAuditLog(

        "USER_UPDATED",

        "USER_MANAGEMENT",

        {

            targetUser:
                normalizedUsername,

            fields:
                Object.keys(
                    updates
                )

        }

    );


    emitAuthEvent(

        AUTH_EVENTS.USER_UPDATED,

        {

            user:
                sanitizeUserForUI(
                    updatedUser
                )

        }

    );


    return sanitizeUserForUI(
        updatedUser
    );

}


/* =========================================================
   CHANGE USER ROLE
========================================================= */

async function changeUserRole(

    username,

    role,

    masterKey

) {

    if(
        !isAdmin()
    ) {

        throw new Error(
            "ACCESS_DENIED"
        );

    }


    if(
        !hasPermission(
            PERMISSIONS.CHANGE_USER_ROLE
        )
    ) {

        throw new Error(
            "ACCESS_DENIED"
        );

    }


    const normalizedUsername =
        normalizeUsername(
            username
        );


    const user =
        await getUserByUsername(
            normalizedUsername
        );


    if(
        !user
    ) {

        throw new Error(
            "USER_NOT_FOUND"
        );

    }


    const newRole =
        normalizeRole(
            role
        );


    /*
       Do not allow the last administrator
       to lose Administrator status.
    */

    if(
        user.profile.role ===
        USER_ROLES.ADMIN &&
        newRole !==
        USER_ROLES.ADMIN
    ) {

        const adminCount =
            await getAdministratorCount();


        if(
            adminCount <= 1
        ) {

            throw new Error(
                "CANNOT_REMOVE_LAST_ADMIN_ROLE"
            );

        }

    }


    if(
        !await verifyMasterSecurityKey(
            masterKey
        )
    ) {

        throw new Error(
            "INVALID_MASTER_KEY"
        );

    }


    await firebaseUpdate(

        getUserReference(
            normalizedUsername
        ),

        {

            "profile/role":
                newRole,

            permissions:
                createPermissions(
                    newRole
                ),

            "metadata/updatedAt":
                Date.now()

        }

    );


    invalidateUsersCache();


    const updatedUser =
        await getUserByUsername(
            normalizedUsername
        );


    if(
        getCurrentUsername() ===
        normalizedUsername
    ) {

        CURRENT_USER =
            updatedUser;

    }


    await writeAuditLog(

        "USER_ROLE_CHANGED",

        "USER_MANAGEMENT",

        {

            targetUser:
                normalizedUsername,

            newRole:
                newRole

        }

    );


    emitAuthEvent(

        AUTH_EVENTS.USER_UPDATED,

        {

            user:
                sanitizeUserForUI(
                    updatedUser
                )

        }

    );


    return sanitizeUserForUI(
        updatedUser
    );

}


/* =========================================================
   UPDATE USER PERMISSIONS
========================================================= */

async function updateUserPermissions(

    username,

    permissions,

    masterKey

) {

    if(
        !isAdmin()
    ) {

        throw new Error(
            "ACCESS_DENIED"
        );

    }


    const normalizedUsername =
        normalizeUsername(
            username
        );


    const user =
        await getUserByUsername(
            normalizedUsername
        );


    if(
        !user
    ) {

        throw new Error(
            "USER_NOT_FOUND"
        );

    }


    if(
        !await verifyMasterSecurityKey(
            masterKey
        )
    ) {

        throw new Error(
            "INVALID_MASTER_KEY"
        );

    }


    await firebaseSet(

        userPermissionsRef(
            normalizedUsername
        ),

        permissions || {}

    );


    await firebaseUpdate(

        userMetadataRef(
            normalizedUsername
        ),

        {

            updatedAt:
                Date.now(),

            permissionsUpdatedAt:
                Date.now(),

            permissionsUpdatedBy:
                getCurrentUsername()

        }

    );


    invalidateUsersCache();


    const updatedUser =
        await getUserByUsername(
            normalizedUsername
        );


    if(
        getCurrentUsername() ===
        normalizedUsername
    ) {

        CURRENT_USER =
            updatedUser;

    }


    await writeAuditLog(

        "USER_PERMISSIONS_UPDATED",

        "USER_MANAGEMENT",

        {

            targetUser:
                normalizedUsername

        }

    );


    return sanitizeUserForUI(
        updatedUser
    );

}


/* =========================================================
   RESET USER PERMISSIONS
========================================================= */

async function resetUserPermissions(

    username,

    masterKey

) {

    if(
        !isAdmin()
    ) {

        throw new Error(
            "ACCESS_DENIED"
        );

    }


    const normalizedUsername =
        normalizeUsername(
            username
        );


    const user =
        await getUserByUsername(
            normalizedUsername
        );


    if(
        !user
    ) {

        throw new Error(
            "USER_NOT_FOUND"
        );

    }


    if(
        !await verifyMasterSecurityKey(
            masterKey
        )
    ) {

        throw new Error(
            "INVALID_MASTER_KEY"
        );

    }


    const permissions =
        createPermissions(
            user.profile.role
        );


    await firebaseSet(

        userPermissionsRef(
            normalizedUsername
        ),

        permissions

    );


    await firebaseUpdate(

        userMetadataRef(
            normalizedUsername
        ),

        {

            updatedAt:
                Date.now(),

            permissionsResetAt:
                Date.now(),

            permissionsResetBy:
                getCurrentUsername()

        }

    );


    invalidateUsersCache();


    const updatedUser =
        await getUserByUsername(
            normalizedUsername
        );


    await writeAuditLog(

        "USER_PERMISSIONS_RESET",

        "USER_MANAGEMENT",

        {

            targetUser:
                normalizedUsername

        }

    );


    return sanitizeUserForUI(
        updatedUser
    );

}


/* =========================================================
   ACTIVATE USER
========================================================= */

async function setUserActiveState(

    username,

    active,

    masterKey

) {

    if(
        !isAdmin()
    ) {

        throw new Error(
            "ACCESS_DENIED"
        );

    }


    if(
        !hasPermission(
            PERMISSIONS.CHANGE_USER_STATUS
        )
    ) {

        throw new Error(
            "ACCESS_DENIED"
        );

    }


    if(
        active
    ) {

        return restoreUser(
            username,
            masterKey
        );

    }


    return disableUser(

        username,

        masterKey

    );

}


/* =========================================================
   DISABLE USER
========================================================= */

async function disableUser(

    username,

    masterKey

) {

    if(
        !isAdmin()
    ) {

        throw new Error(
            "ACCESS_DENIED"
        );

    }


    const normalizedUsername =
        normalizeUsername(
            username
        );


    if(
        normalizedUsername ===
        getCurrentUsername()
    ) {

        throw new Error(
            "CANNOT_DISABLE_CURRENT_USER"
        );

    }


    const user =
        await getUserByUsername(
            normalizedUsername
        );


    if(
        !user
    ) {

        throw new Error(
            "USER_NOT_FOUND"
        );

    }


    /*
       Protect final Administrator.
    */

    if(
        user.profile.role ===
        USER_ROLES.ADMIN
    ) {

        const adminCount =
            await getAdministratorCount();


        if(
            adminCount <= 1
        ) {

            throw new Error(
                "CANNOT_DISABLE_LAST_ADMIN"
            );

        }

    }


    if(
        !await verifyMasterSecurityKey(
            masterKey
        )
    ) {

        throw new Error(
            "INVALID_MASTER_KEY"
        );

    }


    await firebaseUpdate(

        getUserReference(
            normalizedUsername
        ),

        {

            "profile/active":
                false,

            "metadata/updatedAt":
                Date.now(),

            "metadata/deactivatedAt":
                Date.now(),

            "metadata/deactivatedBy":
                getCurrentUsername()

        }

    );


    invalidateUsersCache();


    const updatedUser =
        await getUserByUsername(
            normalizedUsername
        );


    await writeAuditLog(

        "USER_DISABLED",

        "USER_MANAGEMENT",

        {

            targetUser:
                normalizedUsername

        }

    );


    emitAuthEvent(

        AUTH_EVENTS.USER_UPDATED,

        {

            user:
                sanitizeUserForUI(
                    updatedUser
                )

        }

    );


    return sanitizeUserForUI(
        updatedUser
    );

}


/* =========================================================
   RESTORE USER
========================================================= */

async function restoreUser(

    username,

    masterKey

) {

    if(
        !isAdmin()
    ) {

        throw new Error(
            "ACCESS_DENIED"
        );

    }


    const normalizedUsername =
        normalizeUsername(
            username
        );


    const user =
        await getUserByUsername(
            normalizedUsername
        );


    if(
        !user
    ) {

        throw new Error(
            "USER_NOT_FOUND"
        );

    }


    if(
        user.profile.active === true
    ) {

        return sanitizeUserForUI(
            user
        );

    }


    if(
        !await verifyMasterSecurityKey(
            masterKey
        )
    ) {

        throw new Error(
            "INVALID_MASTER_KEY"
        );

    }


    await firebaseUpdate(

        getUserReference(
            normalizedUsername
        ),

        {

            "profile/active":
                true,

            "profile/archived":
                false,

            "metadata/updatedAt":
                Date.now(),

            "metadata/restoredAt":
                Date.now(),

            "metadata/restoredBy":
                getCurrentUsername()

        }

    );


    invalidateUsersCache();


    const updatedUser =
        await getUserByUsername(
            normalizedUsername
        );


    await writeAuditLog(

        "USER_RESTORED",

        "USER_MANAGEMENT",

        {

            targetUser:
                normalizedUsername

        }

    );


    emitAuthEvent(

        AUTH_EVENTS.USER_UPDATED,

        {

            user:
                sanitizeUserForUI(
                    updatedUser
                )

        }

    );


    return sanitizeUserForUI(
        updatedUser
    );

}


/* =========================================================
   ARCHIVE USER
========================================================= */

async function archiveUser(

    username,

    masterKey

) {

    if(
        !isAdmin()
    ) {

        throw new Error(
            "ACCESS_DENIED"
        );

    }


    const normalizedUsername =
        normalizeUsername(
            username
        );


    if(
        normalizedUsername ===
        getCurrentUsername()
    ) {

        throw new Error(
            "CANNOT_ARCHIVE_CURRENT_USER"
        );

    }


    const user =
        await getUserByUsername(
            normalizedUsername
        );


    if(
        !user
    ) {

        throw new Error(
            "USER_NOT_FOUND"
        );

    }


    if(
        user.profile.role ===
        USER_ROLES.ADMIN
    ) {

        const adminCount =
            await getAdministratorCount();


        if(
            adminCount <= 1
        ) {

            throw new Error(
                "CANNOT_ARCHIVE_LAST_ADMIN"
            );

        }

    }


    if(
        !await verifyMasterSecurityKey(
            masterKey
        )
    ) {

        throw new Error(
            "INVALID_MASTER_KEY"
        );

    }


    await firebaseUpdate(

        getUserReference(
            normalizedUsername
        ),

        {

            "profile/active":
                false,

            "profile/archived":
                true,

            "metadata/updatedAt":
                Date.now(),

            "metadata/archivedAt":
                Date.now(),

            "metadata/archivedBy":
                getCurrentUsername()

        }

    );


    invalidateUsersCache();


    await writeAuditLog(

        "USER_ARCHIVED",

        "USER_MANAGEMENT",

        {

            targetUser:
                normalizedUsername

        }

    );


    return true;

}


/* =========================================================
   UNARCHIVE USER
========================================================= */

async function unarchiveUser(

    username,

    masterKey

) {

    if(
        !isAdmin()
    ) {

        throw new Error(
            "ACCESS_DENIED"
        );

    }


    const normalizedUsername =
        normalizeUsername(
            username
        );


    const user =
        await getUserByUsername(
            normalizedUsername
        );


    if(
        !user
    ) {

        throw new Error(
            "USER_NOT_FOUND"
        );

    }


    if(
        !user.profile.archived
    ) {

        return sanitizeUserForUI(
            user
        );

    }


    if(
        !await verifyMasterSecurityKey(
            masterKey
        )
    ) {

        throw new Error(
            "INVALID_MASTER_KEY"
        );

    }


    await firebaseUpdate(

        getUserReference(
            normalizedUsername
        ),

        {

            "profile/active":
                true,

            "profile/archived":
                false,

            "metadata/updatedAt":
                Date.now(),

            "metadata/restoredAt":
                Date.now(),

            "metadata/restoredBy":
                getCurrentUsername()

        }

    );


    invalidateUsersCache();


    const restoredUser =
        await getUserByUsername(
            normalizedUsername
        );


    await writeAuditLog(

        "USER_UNARCHIVED",

        "USER_MANAGEMENT",

        {

            targetUser:
                normalizedUsername

        }

    );


    return sanitizeUserForUI(
        restoredUser
    );

}


/* =========================================================
   DELETE USER
========================================================= */

async function deleteUser(

    username,

    masterKey,

    options = {}

) {

    if(
        !isAdmin()
    ) {

        throw new Error(
            "ACCESS_DENIED"
        );

    }


    const normalizedUsername =
        normalizeUsername(
            username
        );


    if(
        normalizedUsername ===
        getCurrentUsername()
    ) {

        throw new Error(
            "CANNOT_DELETE_CURRENT_USER"
        );

    }


    const user =
        await getUserByUsername(
            normalizedUsername
        );


    if(
        !user
    ) {

        throw new Error(
            "USER_NOT_FOUND"
        );

    }


    /*
       Protect final Administrator.
    */

    if(
        user.profile.role ===
        USER_ROLES.ADMIN
    ) {

        const adminCount =
            await getAdministratorCount();


        if(
            adminCount <= 1
        ) {

            throw new Error(
                "CANNOT_DELETE_LAST_ADMIN"
            );

        }

    }


    if(
        !await verifyMasterSecurityKey(
            masterKey
        )
    ) {

        throw new Error(
            "INVALID_MASTER_KEY"
        );

    }


    /*
       Optional archive instead of hard deletion.
    */

    if(
        options.archive === true
    ) {

        await archiveUser(

            normalizedUsername,

            masterKey

        );


        return {

            success:
                true,

            archived:
                true,

            username:
                normalizedUsername

        };

    }


    await writeAuditLog(

        "USER_DELETE_REQUESTED",

        "USER_MANAGEMENT",

        {

            targetUser:
                normalizedUsername,

            targetRole:
                user.profile.role

        }

    );


    await firebaseRemove(

        getUserReference(
            normalizedUsername
        )

    );


    invalidateUsersCache();


    await writeAuditLog(

        "USER_DELETED",

        "USER_MANAGEMENT",

        {

            targetUser:
                normalizedUsername,

            targetRole:
                user.profile.role

        }

    );


    emitAuthEvent(

        AUTH_EVENTS.USER_DELETED,

        {

            username:
                normalizedUsername,

            role:
                user.profile.role

        }

    );


    return {

        success:
            true,

        archived:
            false,

        username:
            normalizedUsername

    };

}


/* =========================================================
   CHANGE USERNAME
========================================================= */

async function changeUsername(

    currentUsername,

    newUsername,

    masterKey

) {

    if(
        !isAdmin()
    ) {

        throw new Error(
            "ACCESS_DENIED"
        );

    }


    const current =
        normalizeUsername(
            currentUsername
        );


    const validation =
        validateUsername(
            newUsername
        );


    if(
        !validation.valid
    ) {

        throw new Error(
            "INVALID_USERNAME"
        );

    }


    const next =
        validation.value;


    if(
        current ===
        next
    ) {

        return sanitizeUserForUI(

            await getUserByUsername(
                current
            )

        );

    }


    if(
        await userExists(
            next
        )
    ) {

        throw new Error(
            "USERNAME_ALREADY_EXISTS"
        );

    }


    const user =
        await getUserByUsername(
            current
        );


    if(
        !user
    ) {

        throw new Error(
            "USER_NOT_FOUND"
        );

    }


    if(
        !await verifyMasterSecurityKey(
            masterKey
        )
    ) {

        throw new Error(
            "INVALID_MASTER_KEY"
        );

    }


    const migratedUser =
        cloneObject(
            user
        );


    migratedUser.profile.username =
        next;


    migratedUser.metadata.updatedAt =
        Date.now();


    migratedUser.metadata.usernameChangedAt =
        Date.now();


    migratedUser.metadata.usernameChangedBy =
        getCurrentUsername();


    await firebaseSet(

        getUserReference(
            next
        ),

        migratedUser

    );


    await firebaseRemove(

        getUserReference(
            current
        )

    );


    invalidateUsersCache();


    /*
       If the current administrator changed
       their own username, update session.
    */

    if(
        getCurrentUsername() ===
        current
    ) {

        CURRENT_USER =
            await getUserByUsername(
                next
            );


        if(
            CURRENT_SESSION
        ) {

            CURRENT_SESSION.username =
                next;


            saveSession(
                CURRENT_SESSION
            );

        }

    }


    await writeAuditLog(

        "USERNAME_CHANGED",

        "USER_MANAGEMENT",

        {

            previousUsername:
                current,

            newUsername:
                next

        }

    );


    return sanitizeUserForUI(
        migratedUser
    );

}


/* =========================================================
   USER INITIALS
========================================================= */

function getUserInitials(
    fullName
) {

    const parts =
        String(
            fullName || ""
        )
            .trim()
            .split(
                /\s+/
            )
            .filter(
                Boolean
            );


    if(
        parts.length === 0
    ) {

        return "U";

    }


    if(
        parts.length === 1
    ) {

        return parts[0]
            .substring(
                0,
                2
            )
            .toUpperCase();

    }


    return (

        parts[0][0] +

        parts[
            parts.length - 1
        ][0]

    ).toUpperCase();

}


/* =========================================================
   PROFILE PHOTO
========================================================= */

function readPhotoAsDataURL(
    file
) {

    return new Promise(

        (
            resolve,
            reject
        ) => {

            if(
                !file
            ) {

                resolve(
                    null
                );


                return;

            }


            if(
                !file.type.startsWith(
                    "image/"
                )
            ) {

                reject(
                    new Error(
                        "INVALID_PHOTO"
                    )
                );


                return;

            }


            /*
               5 MB maximum source image.
            */

            if(
                file.size >
                5 * 1024 * 1024
            ) {

                reject(
                    new Error(
                        "PHOTO_TOO_LARGE"
                    )
                );


                return;

            }


            const reader =
                new FileReader();


            reader.onload =
                event => {

                    resolve(
                        event.target.result
                    );

                };


            reader.onerror =
                () => {

                    reject(
                        new Error(
                            "PHOTO_READ_FAILED"
                        )
                    );

                };


            reader.readAsDataURL(
                file
            );

        }

    );

}


/* =========================================================
   CURRENT USER
========================================================= */

function getCurrentUser() {

    return CURRENT_USER
        ? sanitizeUserForUI(
            CURRENT_USER
        )
        : null;

}


function getCurrentUsername() {

    return (

        CURRENT_USER
            ?.profile
            ?.username ||

        null

    );

}


function getCurrentFullName() {

    return (

        CURRENT_USER
            ?.profile
            ?.fullName ||

        "Guest User"

    );

}


function getCurrentRole() {

    return (

        CURRENT_USER
            ?.profile
            ?.role ||

        null

    );

}


function getCurrentRoleName() {

    return getRoleName(
        getCurrentRole()
    );

}


function getCurrentPhoto() {

    return (

        CURRENT_USER
            ?.profile
            ?.photo ||

        null

    );

}


/* =========================================================
   AUTH STATE
========================================================= */

function isLogged() {

    return (
        CURRENT_USER !== null
    );

}


function isGuest() {

    return (
        CURRENT_USER === null
    );

}


function isAuthReady() {

    return (
        AUTH_READY === true
    );

}


function isFirstInstallation() {

    return (
        FIRST_INSTALLATION === true
    );

}


/* =========================================================
   ROLE CHECKS
========================================================= */

function hasRole(
    role
) {

    if(
        !CURRENT_USER
    ) {

        return false;

    }


    return (

        getCurrentRole() ===
        normalizeRole(
            role
        )

    );

}


function isAdmin() {

    return hasRole(
        USER_ROLES.ADMIN
    );

}


function isFinancial() {

    return hasRole(
        USER_ROLES.FINANCIAL
    );

}


function isUser() {

    return hasRole(
        USER_ROLES.USER
    );

}


/* =========================================================
   PERMISSION CHECK
========================================================= */

function hasPermission(
    permission
) {

    if(
        !CURRENT_USER
    ) {

        return false;

    }


    /*
       Administrator has full application access.

       Database Rules must still enforce security.
    */

    if(
        isAdmin()
    ) {

        return true;

    }


    return (

        CURRENT_USER
            ?.permissions
            ?.[permission] === true

    );

}


/* =========================================================
   REQUIRE LOGIN
========================================================= */

function requireLogin() {

    if(
        isLogged()
    ) {

        refreshSession();


        return true;

    }


    emitAuthEvent(

        AUTH_EVENTS.ACCESS_DENIED,

        {

            reason:
                "NOT_AUTHENTICATED"

        }

    );


    if(
        typeof window.openLoginModal ===
        "function"
    ) {

        window.openLoginModal();

    }


    return false;

}


/* =========================================================
   REQUIRE PERMISSION
========================================================= */

function requirePermission(
    permission
) {

    if(
        !requireLogin()
    ) {

        return false;

    }


    if(
        hasPermission(
            permission
        )
    ) {

        refreshSession();


        return true;

    }


    emitAuthEvent(

        AUTH_EVENTS.ACCESS_DENIED,

        {

            reason:
                "PERMISSION_DENIED",

            permission:
                permission

        }

    );


    if(
        typeof window.showAccessDeniedModal ===
        "function"
    ) {

        window.showAccessDeniedModal(
            permission
        );

    }


    return false;

}


/* =========================================================
   REQUIRE ROLE
========================================================= */

function requireRole(
    roles
) {

    if(
        !requireLogin()
    ) {

        return false;

    }


    const roleList =
        Array.isArray(
            roles
        )
            ? roles
            : [roles];


    const allowed =
        roleList.some(

            role =>

                hasRole(
                    role
                )

        );


    if(
        allowed
    ) {

        return true;

    }


    emitAuthEvent(

        AUTH_EVENTS.ACCESS_DENIED,

        {

            reason:
                "ROLE_DENIED",

            roles:
                roleList

        }

    );


    if(
        typeof window.showAccessDeniedModal ===
        "function"
    ) {

        window.showAccessDeniedModal(
            "role"
        );

    }


    return false;

}


/* =========================================================
   AUDIT LOG
========================================================= */

async function writeAuditLog(

    action,

    module =
        "AUTH",

    details =
        {}

) {

    try {

        const reference =
            firebasePush(
                logsRef()
            );


        await firebaseSet(

            reference,

            {

                timestamp:
                    Date.now(),

                action:
                    action,

                module:
                    module,

                username:
                    getCurrentUsername() ||
                    details.username ||
                    null,

                role:
                    getCurrentRole() ||
                    details.role ||
                    null,

                details:
                    cloneObject(
                        details
                    )

            }

        );


        return true;

    }
    catch(error) {

        /*
           Logging must never break the actual
           application operation.
        */

        console.warn(

            "AUTH — Audit log failed:",

            error

        );


        return false;

    }

}


/* =========================================================
   AUTH ERROR MESSAGES
========================================================= */

function getAuthErrorMessage(
    errorCode
) {

    const messages = {

        MISSING_CREDENTIALS:
            "Please enter your username and password.",

        INVALID_CREDENTIALS:
            "Incorrect username or password.",

        ACCOUNT_DISABLED:
            "This account is currently disabled.",

        ACCOUNT_ARCHIVED:
            "This account has been archived.",

        ACCOUNT_NOT_CONFIGURED:
            "This account is not correctly configured.",

        INVALID_USERNAME:
            "The username is invalid.",

        INVALID_PASSWORD:
            "The password must contain at least 6 characters.",

        INVALID_FULL_NAME:
            "Please enter the full name.",

        USERNAME_ALREADY_EXISTS:
            "That username is already in use.",

        INVALID_MASTER_KEY:
            "The Master Security Key must contain at least 8 characters.",

        ADMINISTRATOR_ALREADY_EXISTS:
            "An Administrator already exists.",

        CURRENT_PASSWORD_INVALID:
            "The current password is incorrect.",

        CANNOT_DISABLE_CURRENT_USER:
            "You cannot disable your own account.",

        CANNOT_DELETE_CURRENT_USER:
            "You cannot delete your own account.",

        CANNOT_ARCHIVE_CURRENT_USER:
            "You cannot archive your own account.",

        CANNOT_DISABLE_LAST_ADMIN:
            "The last Administrator cannot be disabled.",

        CANNOT_DELETE_LAST_ADMIN:
            "The last Administrator cannot be removed.",

        CANNOT_ARCHIVE_LAST_ADMIN:
            "The last Administrator cannot be archived.",

        CANNOT_REMOVE_LAST_ADMIN_ROLE:
            "The last Administrator cannot lose Administrator status.",

        CANNOT_UNARCHIVE:
            "This user cannot be restored.",

        NOT_AUTHENTICATED:
            "You must be signed in.",

        ACCESS_DENIED:
            "You do not have permission to perform this action.",

        USER_NOT_FOUND:
            "The requested user could not be found.",

        LOGIN_ERROR:
            "Unable to complete the login.",

        INVALID_PHOTO:
            "Please select a valid image.",

        PHOTO_TOO_LARGE:
            "The selected profile photo is too large.",

        PHOTO_READ_FAILED:
            "The profile photo could not be read.",

        NOT_CONNECTED:
            "Unable to connect to the database."

    };


    return (

        messages[
            errorCode
        ] ||

        "An authentication error occurred."

    );

}


/* =========================================================
   SESSION ACTIVITY
========================================================= */

function registerSessionActivity() {

    if(
        !CURRENT_USER ||
        !CURRENT_SESSION
    ) {

        return;

    }


    const now =
        Date.now();


    /*
       Prevent constant localStorage writes.
    */

    if(
        now -
        LAST_ACTIVITY_UPDATE <
        60 * 1000
    ) {

        return;

    }


    LAST_ACTIVITY_UPDATE =
        now;


    refreshSession();

}


const ACTIVITY_EVENTS = [

    "click",

    "keydown",

    "mousemove",

    "scroll",

    "touchstart"

];


ACTIVITY_EVENTS.forEach(

    eventName => {

        window.addEventListener(

            eventName,

            registerSessionActivity,

            {

                passive:
                    true

            }

        );

    }

);


/* =========================================================
   AUTOMATIC SESSION CHECK
========================================================= */

setInterval(

    async () => {

        if(
            !CURRENT_SESSION ||
            !CURRENT_USER
        ) {

            return;

        }


        if(
            !isSessionValid(
                CURRENT_SESSION
            )
        ) {

            const username =
                getCurrentUsername();


            CURRENT_USER =
                null;


            clearSession();


            await writeAuditLog(

                "SESSION_EXPIRED",

                "AUTH",

                {

                    username:
                        username

                }

            );


            emitAuthEvent(

                AUTH_EVENTS.SESSION_EXPIRED

            );

        }

    },

    60 * 1000

);


/* =========================================================
   PUBLIC AUTH API
========================================================= */

const authAPI = {

    /* ---------------------------------
       State
    --------------------------------- */

    getCurrentUser,

    getCurrentUsername,

    getCurrentFullName,

    getCurrentRole,

    getCurrentRoleName,

    getCurrentPhoto,

    isLogged,

    isGuest,

    isAuthReady,

    isFirstInstallation,


    /* ---------------------------------
       Roles
    --------------------------------- */

    hasRole,

    isAdmin,

    isFinancial,

    isUser,


    /* ---------------------------------
       Permissions
    --------------------------------- */

    hasPermission,

    requireLogin,

    requirePermission,

    requireRole,


    /* ---------------------------------
       Authentication
    --------------------------------- */

    initialiseAuthentication,

    loginUser,

    logoutUser,

    restoreSession,


    /* ---------------------------------
       First installation
    --------------------------------- */

    createFirstAdministrator,

    generateMasterKey,

    verifyMasterSecurityKey,


    /* ---------------------------------
       Users
    --------------------------------- */

    createUser,

    getUserByUsername,

    userExists,

    loadAllUsers,

    searchUsers,

    getAdministratorCount,

    adminUpdateUser,

    changeUsername,

    changeUserRole,

    updateUserPermissions,

    resetUserPermissions,

    setUserActiveState,

    disableUser,

    restoreUser,

    archiveUser,

    unarchiveUser,

    deleteUser,


    /* ---------------------------------
       Passwords
    --------------------------------- */

    changeOwnPassword,

    adminResetUserPassword,


    /* ---------------------------------
       Profile
    --------------------------------- */

    updateCurrentUserProfile,

    readPhotoAsDataURL,


    /* ---------------------------------
       Utilities
    --------------------------------- */

    normalizeUsername,

    normalizeRole,

    validateUsername,

    validatePassword,

    getRoleName,

    getUserInitials,

    sanitizeUserForUI,

    getAuthErrorMessage,


    /* ---------------------------------
       Security / Logs
    --------------------------------- */

    writeAuditLog

};


/* =========================================================
   GLOBAL AUTH BRIDGE
========================================================= */

window.authSystem =
    authAPI;


/*
   Compatibility helpers for the HTML / modal layer.
*/

window.loginUser =
    loginUser;


window.logoutUser =
    logoutUser;


window.createUser =
    createUser;


window.getCurrentUser =
    getCurrentUser;


window.getCurrentRole =
    getCurrentRole;


window.isAdmin =
    isAdmin;


window.isFinancial =
    isFinancial;


window.isUser =
    isUser;


window.hasPermission =
    hasPermission;


window.requirePermission =
    requirePermission;


window.disableUser =
    disableUser;


window.restoreUser =
    restoreUser;


window.archiveUser =
    archiveUser;


window.unarchiveUser =
    unarchiveUser;


window.deleteUser =
    deleteUser;


window.searchUsers =
    searchUsers;


/* =========================================================
   AUTH READY CALLBACK
========================================================= */

window.addEventListener(

    AUTH_EVENTS.READY,

    event => {

        if(
            typeof window.onAuthenticationReady ===
            "function"
        ) {

            window.onAuthenticationReady(

                event.detail?.user ||
                null

            );

        }

    }

);


/* =========================================================
   EXPORTS
========================================================= */

export {

    /* Paths */

    PATHS,


    /* Roles */

    USER_ROLES,

    ROLE_NAMES,


    /* Permissions */

    PERMISSIONS,

    DEFAULT_PERMISSIONS,


    /* Events */

    AUTH_EVENTS,


    /* State */

    getCurrentUser,

    getCurrentUsername,

    getCurrentFullName,

    getCurrentRole,

    getCurrentRoleName,

    getCurrentPhoto,

    isLogged,

    isGuest,

    isAuthReady,

    isFirstInstallation,


    /* Authentication */

    initialiseAuthentication,

    loginUser,

    logoutUser,

    restoreSession,


    /* First installation */

    createFirstAdministrator,

    generateMasterKey,

    verifyMasterSecurityKey,


    /* Users */

    createUser,

    getUserByUsername,

    userExists,

    loadAllUsers,

    searchUsers,

    getAdministratorCount,

    adminUpdateUser,

    changeUsername,

    changeUserRole,

    updateUserPermissions,

    resetUserPermissions,

    setUserActiveState,

    disableUser,

    restoreUser,

    archiveUser,

    unarchiveUser,

    deleteUser,


    /* Passwords */

    changeOwnPassword,

    adminResetUserPassword,


    /* Profile */

    updateCurrentUserProfile,

    readPhotoAsDataURL,


    /* Utilities */

    normalizeUsername,

    normalizeRole,

    validateUsername,

    validatePassword,

    getRoleName,

    getUserInitials,

    sanitizeUserForUI,

    getAuthErrorMessage,


    /* Security */

    hashPassword,

    generateSalt,


    /* Logs */

    writeAuditLog

};

/* =========================================================
   CONTRACT MANAGEMENT — GLOBAL FOOTER
   ---------------------------------------------------------
   Footer visibility for the dashboard UI.

   HOME:
   - Footer hidden

   CONTRACT SECTIONS:
   - Footer visible

   PDF:
   - Not affected by these functions
========================================================= */


/* =========================================================
   SHOW FOOTER
========================================================= */

function showGlobalFooter(){

    const footer =
        document.getElementById("globalFooter");


    if(!footer){

        return;

    }


    footer.style.display =
        "flex";

}


/* =========================================================
   HIDE FOOTER
========================================================= */

function hideGlobalFooter(){

    const footer =
        document.getElementById("globalFooter");


    if(!footer){

        return;

    }


    footer.style.display =
        "none";

}


/* =========================================================
   CONTRACT MANAGEMENT FOOTER VISIBILITY
========================================================= */

function updateGlobalFooterVisibility(){

    const footer =
        document.getElementById("globalFooter");


    if(!footer){

        return;

    }


    /*
     * -----------------------------------------------------
     * CONTRACT MANAGEMENT HOME
     * -----------------------------------------------------
     *
     * If the main dashboard/home container is visible,
     * keep the footer hidden.
     */

    const home =
        document.getElementById("home");


    if(
        home &&
        home.style.display !== "none"
    ){

        hideGlobalFooter();

        return;

    }


    /*
     * -----------------------------------------------------
     * DETECT ACTIVE CONTRACT SECTION
     * -----------------------------------------------------
     *
     * Contract sections are dynamically created, so we
     * don't depend on a fixed list of section IDs.
     *
     * We look for visible section containers belonging
     * to the Contract Management dashboard.
     */

    const visibleSections =
        document.querySelectorAll(
            '[id^="contractSection"], ' +
            '.contract-section, ' +
            '.contract-dashboard-section'
        );


    let hasVisibleSection =
        false;


    visibleSections.forEach(
        section => {

            if(
                !section
            ){

                return;

            }


            const style =
                window.getComputedStyle(
                    section
                );


            if(
                style.display !== "none" &&
                style.visibility !== "hidden" &&
                section.offsetHeight > 0
            ){

                hasVisibleSection =
                    true;

            }

        }
    );


    /*
     * -----------------------------------------------------
     * SECTION FOUND
     * -----------------------------------------------------
     */

    if(
        hasVisibleSection
    ){

        showGlobalFooter();

        return;

    }


    /*
     * -----------------------------------------------------
     * FALLBACK
     * -----------------------------------------------------
     *
     * If we are not on Home and the dashboard itself is
     * active, keep the footer visible.
     *
     * This is useful for dynamically generated sections.
     */

    const dashboard =
        document.getElementById(
            "contractManagementDashboard"
        );


    if(
        dashboard &&
        dashboard.style.display !== "none"
    ){

        showGlobalFooter();

        return;

    }


    /*
     * -----------------------------------------------------
     * NOTHING ACTIVE
     * -----------------------------------------------------
     */

    hideGlobalFooter();

}


/* =========================================================
   INITIALISE FOOTER
========================================================= */

document.addEventListener(
    "DOMContentLoaded",
    function(){

        updateGlobalFooterVisibility();

    }
);


/* =========================================================
   OBSERVE DYNAMIC SECTION CHANGES
   ---------------------------------------------------------
   Important because Contract Management sections can be
   created / removed dynamically.
========================================================= */

if(
    typeof MutationObserver !==
    "undefined"
){

    const footerObserver =
        new MutationObserver(
            function(){

                updateGlobalFooterVisibility();

            }
        );


    footerObserver.observe(

        document.body,

        {

            childList:
                true,

            subtree:
                true,

            attributes:
                true,

            attributeFilter:
                [
                    "style",
                    "class"
                ]

        }

    );

}

/* =========================================================
   GLOBAL EXPORTS
   ---------------------------------------------------------
   Makes the footer functions available throughout the
   Contract Management Dashboard.
========================================================= */

window.showGlobalFooter =
    showGlobalFooter;

window.hideGlobalFooter =
    hideGlobalFooter;

window.updateGlobalFooterVisibility =
    updateGlobalFooterVisibility;