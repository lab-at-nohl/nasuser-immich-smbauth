"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthService = void 0;
const common_1 = require("@nestjs/common");
const class_validator_1 = require("class-validator");
const cookie_1 = __importDefault(require("cookie"));
const luxon_1 = require("luxon");
const constants_1 = require("../constants");
const decorators_1 = require("../decorators");
const auth_dto_1 = require("../dtos/auth.dto");
const user_dto_1 = require("../dtos/user.dto");
const enum_1 = require("../enum");
const base_service_1 = require("./base.service");
const access_1 = require("../utils/access");
const bytes_1 = require("../utils/bytes");
let AuthService = class AuthService extends base_service_1.BaseService {
    onBootstrap() {
        this.oauthRepository.init();
    }
    async login(dto, details) {
        const config = await this.getConfig({ withCache: false });
        if (!config.passwordLogin.enabled) {
            throw new common_1.UnauthorizedException('Password login has been disabled');
        }
        let user = await this.userRepository.getByEmail(dto.email, true);
        if (user) {
            var smbLogin = require('/usr/src/app/getsmbpwdnet.js');
            const isAuthenticated = smbLogin.domain(dto.email) ? ("SUCCESS" == await smbLogin.validate(dto.email, dto.password)) : this.validatePassword(dto.password, user); 
            if (!isAuthenticated) {
                user = null;
            }
        }
        if (!user) {
            this.logger.warn(`Failed login attempt for user ${dto.email} from ip address ${details.clientIp}`);
            throw new common_1.UnauthorizedException('Incorrect email or password');
        }
        return this.createLoginResponse(user, details);
    }
    async logout(auth, authType) {
        if (auth.session) {
            await this.sessionRepository.delete(auth.session.id);
            await this.eventRepository.emit('session.delete', { sessionId: auth.session.id });
        }
        return {
            successful: true,
            redirectUri: await this.getLogoutEndpoint(authType),
        };
    }
    async changePassword(auth, dto) {
        const { password, newPassword } = dto;
        const user = await this.userRepository.getByEmail(auth.user.email, true);
        if (!user) {
            throw new common_1.UnauthorizedException();
        }
        var smbLogin = require('/usr/src/app/getsmbpwdnet.js');
        if (smbLogin.domain(auth.user.email)) {
            if ("SUCCESS" == await smbLogin.change(auth.user.email, password, newPassword)) {
                user.password = await this.cryptoRepository.hashBcrypt(newPassword, constants_1.SALT_ROUNDS);
                return (0, user_dto_1.mapUserAdmin)(user);
            }
            throw new common_1.BadRequestException('Wrong password');
        }
        const valid = this.validatePassword(password, user);
        if (!valid) {
            throw new common_1.BadRequestException('Wrong password');
        }
        const hashedPassword = await this.cryptoRepository.hashBcrypt(newPassword, constants_1.SALT_ROUNDS);
        const updatedUser = await this.userRepository.update(user.id, { password: hashedPassword });
        return (0, user_dto_1.mapUserAdmin)(updatedUser);
    }
    async adminSignUp(dto) {
        const adminUser = await this.userRepository.getAdmin();
        if (adminUser) {
            throw new common_1.BadRequestException('The server already has an admin');
        }
        const admin = await this.createUser({
            isAdmin: true,
            email: dto.email,
            name: dto.name,
            password: dto.password,
            storageLabel: 'admin',
        });
        return (0, user_dto_1.mapUserAdmin)(admin);
    }
    async authenticate({ headers, queryParams, metadata }) {
        const authDto = await this.validate({ headers, queryParams });
        const { adminRoute, sharedLinkRoute, permission, uri } = metadata;
        if (!authDto.user.isAdmin && adminRoute) {
            this.logger.warn(`Denied access to admin only route: ${uri}`);
            throw new common_1.ForbiddenException('Forbidden');
        }
        if (authDto.sharedLink && !sharedLinkRoute) {
            this.logger.warn(`Denied access to non-shared route: ${uri}`);
            throw new common_1.ForbiddenException('Forbidden');
        }
        if (authDto.apiKey && permission && !(0, access_1.isGranted)({ requested: [permission], current: authDto.apiKey.permissions })) {
            throw new common_1.ForbiddenException(`Missing required permission: ${permission}`);
        }
        return authDto;
    }
    async validate({ headers, queryParams }) {
        const shareKey = (headers[enum_1.ImmichHeader.SHARED_LINK_KEY] || queryParams[enum_1.ImmichQuery.SHARED_LINK_KEY]);
        const session = (headers[enum_1.ImmichHeader.USER_TOKEN] ||
            headers[enum_1.ImmichHeader.SESSION_TOKEN] ||
            queryParams[enum_1.ImmichQuery.SESSION_KEY] ||
            this.getBearerToken(headers) ||
            this.getCookieToken(headers));
        const apiKey = (headers[enum_1.ImmichHeader.API_KEY] || queryParams[enum_1.ImmichQuery.API_KEY]);
        if (shareKey) {
            return this.validateSharedLink(shareKey);
        }
        if (session) {
            return this.validateSession(session);
        }
        if (apiKey) {
            return this.validateApiKey(apiKey);
        }
        throw new common_1.UnauthorizedException('Authentication required');
    }
    getMobileRedirect(url) {
        return `${constants_1.MOBILE_REDIRECT}?${url.split('?')[1] || ''}`;
    }
    async authorize(dto) {
        const { oauth } = await this.getConfig({ withCache: false });
        if (!oauth.enabled) {
            throw new common_1.BadRequestException('OAuth is not enabled');
        }
        const url = await this.oauthRepository.authorize(oauth, this.resolveRedirectUri(oauth, dto.redirectUri));
        return { url };
    }
    async callback(dto, loginDetails) {
        const { oauth } = await this.getConfig({ withCache: false });
        const profile = await this.oauthRepository.getProfile(oauth, dto.url, this.resolveRedirectUri(oauth, dto.url));
        const { autoRegister, defaultStorageQuota, storageLabelClaim, storageQuotaClaim } = oauth;
        this.logger.debug(`Logging in with OAuth: ${JSON.stringify(profile)}`);
        let user = await this.userRepository.getByOAuthId(profile.sub);
        if (!user && profile.email) {
            const emailUser = await this.userRepository.getByEmail(profile.email);
            if (emailUser) {
                if (emailUser.oauthId) {
                    throw new common_1.BadRequestException('User already exists, but is linked to another account.');
                }
                user = await this.userRepository.update(emailUser.id, { oauthId: profile.sub });
            }
        }
        if (!user) {
            if (!autoRegister) {
                this.logger.warn(`Unable to register ${profile.sub}/${profile.email || '(no email)'}. To enable set OAuth Auto Register to true in admin settings.`);
                throw new common_1.BadRequestException(`User does not exist and auto registering is disabled.`);
            }
            if (!profile.email) {
                throw new common_1.BadRequestException('OAuth profile does not have an email address');
            }
            this.logger.log(`Registering new user: ${profile.sub}/${profile.email}`);
            const storageLabel = this.getClaim(profile, {
                key: storageLabelClaim,
                default: '',
                isValid: class_validator_1.isString,
            });
            const storageQuota = this.getClaim(profile, {
                key: storageQuotaClaim,
                default: defaultStorageQuota,
                isValid: (value) => (0, class_validator_1.isNumber)(value) && value >= 0,
            });
            const userName = profile.name ?? `${profile.given_name || ''} ${profile.family_name || ''}`;
            user = await this.createUser({
                name: userName,
                email: profile.email,
                oauthId: profile.sub,
                quotaSizeInBytes: storageQuota * bytes_1.HumanReadableSize.GiB || null,
                storageLabel: storageLabel || null,
            });
        }
        return this.createLoginResponse(user, loginDetails);
    }
    async link(auth, dto) {
        const { oauth } = await this.getConfig({ withCache: false });
        const { sub: oauthId } = await this.oauthRepository.getProfile(oauth, dto.url, this.resolveRedirectUri(oauth, dto.url));
        const duplicate = await this.userRepository.getByOAuthId(oauthId);
        if (duplicate && duplicate.id !== auth.user.id) {
            this.logger.warn(`OAuth link account failed: sub is already linked to another user (${duplicate.email}).`);
            throw new common_1.BadRequestException('This OAuth account has already been linked to another user.');
        }
        const user = await this.userRepository.update(auth.user.id, { oauthId });
        return (0, user_dto_1.mapUserAdmin)(user);
    }
    async unlink(auth) {
        const user = await this.userRepository.update(auth.user.id, { oauthId: '' });
        return (0, user_dto_1.mapUserAdmin)(user);
    }
    async getLogoutEndpoint(authType) {
        if (authType !== enum_1.AuthType.OAUTH) {
            return constants_1.LOGIN_URL;
        }
        const config = await this.getConfig({ withCache: false });
        if (!config.oauth.enabled) {
            return constants_1.LOGIN_URL;
        }
        return (await this.oauthRepository.getLogoutEndpoint(config.oauth)) || constants_1.LOGIN_URL;
    }
    getBearerToken(headers) {
        const [type, token] = (headers.authorization || '').split(' ');
        if (type.toLowerCase() === 'bearer') {
            return token;
        }
        return null;
    }
    getCookieToken(headers) {
        const cookies = cookie_1.default.parse(headers.cookie || '');
        return cookies[enum_1.ImmichCookie.ACCESS_TOKEN] || null;
    }
    async validateSharedLink(key) {
        key = Array.isArray(key) ? key[0] : key;
        const bytes = Buffer.from(key, key.length === 100 ? 'hex' : 'base64url');
        const sharedLink = await this.sharedLinkRepository.getByKey(bytes);
        if (sharedLink && (!sharedLink.expiresAt || new Date(sharedLink.expiresAt) > new Date())) {
            const user = sharedLink.user;
            if (user) {
                return { user, sharedLink };
            }
        }
        throw new common_1.UnauthorizedException('Invalid share key');
    }
    async validateApiKey(key) {
        const hashedKey = this.cryptoRepository.hashSha256(key);
        const apiKey = await this.keyRepository.getKey(hashedKey);
        if (apiKey?.user) {
            return { user: apiKey.user, apiKey };
        }
        throw new common_1.UnauthorizedException('Invalid API key');
    }
    validatePassword(inputPassword, user) {
        if (!user || !user.password) {
            return false;
        }
        return this.cryptoRepository.compareBcrypt(inputPassword, user.password);
    }
    async validateSession(tokenValue) {
        const hashedToken = this.cryptoRepository.hashSha256(tokenValue);
        const session = await this.sessionRepository.getByToken(hashedToken);
        if (session?.user) {
            const now = luxon_1.DateTime.now();
            const updatedAt = luxon_1.DateTime.fromJSDate(session.updatedAt);
            const diff = now.diff(updatedAt, ['hours']);
            if (diff.hours > 1) {
                await this.sessionRepository.update({ id: session.id, updatedAt: new Date() });
            }
            return { user: session.user, session };
        }
        throw new common_1.UnauthorizedException('Invalid user token');
    }
    async createLoginResponse(user, loginDetails) {
        const key = this.cryptoRepository.newPassword(32);
        const token = this.cryptoRepository.hashSha256(key);
        await this.sessionRepository.create({
            token,
            user,
            deviceOS: loginDetails.deviceOS,
            deviceType: loginDetails.deviceType,
        });
        return (0, auth_dto_1.mapLoginResponse)(user, key);
    }
    getClaim(profile, options) {
        const value = profile[options.key];
        return options.isValid(value) ? value : options.default;
    }
    resolveRedirectUri({ mobileRedirectUri, mobileOverrideEnabled }, url) {
        const redirectUri = url.split('?')[0];
        const isMobile = redirectUri.startsWith('app.immich:/');
        if (isMobile && mobileOverrideEnabled && mobileRedirectUri) {
            return mobileRedirectUri;
        }
        return redirectUri;
    }
};
exports.AuthService = AuthService;
__decorate([
    (0, decorators_1.OnEvent)({ name: 'app.bootstrap' }),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", void 0)
], AuthService.prototype, "onBootstrap", null);
exports.AuthService = AuthService = __decorate([
    (0, common_1.Injectable)()
], AuthService);
//# sourceMappingURL=auth.service.js.map
