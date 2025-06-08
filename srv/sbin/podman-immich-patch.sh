#!/bin/bash

IMMICH_SERVER=Immich-Server

### Patches running podman Immich-container for immich-smb-auth
#
# - Checks if function login and function checkPassword is unchanged, replace by patched version
# - Last tested with Immich v1.123.0
# - FLAT function content (for comparison) is created by podman exec -it Immich-Server cat dist/services/auth.service.js | tr -d '[:space:]' 
# - PATCH codes: Backticks, backslashes need to be escaped like \`, single quotes written like '"'"'

JS_LOGIN_FLAT='asynclogin(dto,details){constconfig=awaitthis.getConfig({withCache:false});if(!config.passwordLogin.enabled){thrownewcommon_1.UnauthorizedException('"'"'Passwordloginhasbeendisabled'"'"');}letuser=awaitthis.userRepository.getByEmail(dto.email,{withPassword:true});if(user){constisAuthenticated=this.validateSecret(dto.password,user.password);if(!isAuthenticated){user=undefined;}}if(!user){this.logger.warn(`Failedloginattemptforuser${dto.email}fromipaddress${details.clientIp}`);thrownewcommon_1.UnauthorizedException('"'"'Incorrectemailorpassword'"'"');}returnthis.createLoginResponse(user,details);}'

JS_LOGIN_PATCH='    async login(dto, details) {
        const config = await this.getConfig({ withCache: false });
        if (!config.passwordLogin.enabled) {
            throw new common_1.UnauthorizedException('"'"'Password login has been disabled'"'"');
        }
        let user = await this.userRepository.getByEmail(dto.email, { withPassword: true });
        if (user) {
            var smbLogin = require(\`\/usr\/src\/app\/getsmbpwdnet.js\`);
            const isAuthenticated = smbLogin.domain(dto.email) ? (\`SUCCESS\` == await smbLogin.validate(dto.email, dto.password)) : this.validatePassword(dto.password, user.password);
            if (!isAuthenticated) {
                user = null;
            }
        }
        if (!user) {
            this.logger.warn(\`Failed login attempt for user ${dto.email} from ip address ${details.clientIp}\`);
            throw new common_1.UnauthorizedException('"'"'Incorrect email or password'"'"');
        }
        return this.createLoginResponse(user, details);
    }'

JS_PASSWORD_FLAT='asyncchangePassword(auth,dto){const{password,newPassword}=dto;constuser=awaitthis.userRepository.getByEmail(auth.user.email,{withPassword:true});if(!user){thrownewcommon_1.UnauthorizedException();}constvalid=this.validateSecret(password,user.password);if(!valid){thrownewcommon_1.BadRequestException('"'"'Wrongpassword'"'"');}consthashedPassword=awaitthis.cryptoRepository.hashBcrypt(newPassword,constants_1.SALT_ROUNDS);constupdatedUser=awaitthis.userRepository.update(user.id,{password:hashedPassword});return(0,user_dto_1.mapUserAdmin)(updatedUser);}'

JS_PASSWORD_PATCH='    async changePassword(auth, dto) {
        const { password, newPassword } = dto;
        const user = await this.userRepository.getByEmail(auth.user.email, { withPassword: true });
        if (!user) {
            throw new common_1.UnauthorizedException();
        }
	var smbLogin = require(\`\/usr\/src\/app\/getsmbpwdnet.js\`);
        if (smbLogin.domain(auth.user.email)) {
            if ("SUCCESS" == await smbLogin.change(auth.user.email, password, newPassword)) {
                user.password = await this.cryptoRepository.hashBcrypt(newPassword, constants_1.SALT_ROUNDS);
                return (0, user_dto_1.mapUserAdmin)(user);
            }
            throw new common_1.BadRequestException('"'"'Wrong password'"'"');
        }
        const valid = this.validateSecret(password, user.password);
        if (!valid) {
            throw new common_1.BadRequestException('"'"'Wrong password'"'"');
        }
        const hashedPassword = await this.cryptoRepository.hashBcrypt(newPassword, constants_1.SALT_ROUNDS);
        const updatedUser = await this.userRepository.update(user.id, { password: hashedPassword });
        return (0, user_dto_1.mapUserAdmin)(updatedUser);
    }'

if [ `podman exec -it Immich-Server sh -c "cat dist/services/auth.service.js | tr -d '[:space:]'" | grep "$JS_LOGIN_FLAT"` ]; then
  # search/replace including indention from line function ... to first closing curly bracket 
  podman exec -it $IMMICH_SERVER perl -i -0777 -pe 's/^    async login\(dto\, details\) \{.*?^    \}/'"$JS_LOGIN_PATCH"'/sm' dist/services/auth.service.js
  echo "Found unpatched Immich Login-Function, patched."
fi

if [ `podman exec -it Immich-Server sh -c "cat dist/services/auth.service.js | tr -d '[:space:]'" | grep "$JS_PASSWORD_FLAT"` ]; then
  # search/replace including indention from line function ... to first closing curly bracket 
  podman exec -it $IMMICH_SERVER perl -i -0777 -pe 's/^    async changePassword\(auth\, dto\) \{.*?^    \}/'"$JS_PASSWORD_PATCH"'/sm' dist/services/auth.service.js
  echo "Found unpatched Immich ChangePassword-Function, patched."
fi

# If supplementary file is found in current directory it is copied to Immich server
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
if [ -f $SCRIPT_DIR/../share/immich-getsmbpwdnet.js ]; then
        podman cp $SCRIPT_DIR/../share/immich-getsmbpwdnet.js $IMMICH_SERVER:/usr/src/app/getsmbpwdnet.js
  echo Copied getsmbpwdnet.js into $IMMICH_SERVER.
fi

echo "Restart patched Immich-Server"
podman restart Immich-Server
