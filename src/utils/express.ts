export const matchRoute = (
  path: string,
  method: string
  // tslint:disable-next-line: no-any
): ((r: any) => boolean) => {
  // tslint:disable-next-line: no-any
  return (r: any) =>
    r.route &&
    r.route.path === path &&
    r.route.methods &&
    r.route.methods[method];
};
