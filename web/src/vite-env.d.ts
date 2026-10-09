/// <reference types="vite/client" />

// Declare CSS modules so TypeScript knows they exist
declare module "*.css" {
  export const content: string;
  export default content;
}
