import { SetMetadata } from '@nestjs/common';

export const AdminAllowedArgs = (...adminAllowedArgs: string[]) =>
  SetMetadata('adminAllowedArgs', adminAllowedArgs);
