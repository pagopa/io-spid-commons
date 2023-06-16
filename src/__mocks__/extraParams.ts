import * as t from "io-ts";

export const expectedExtraParams = {
  aNewParam: "a new param",
  anotherParam: 2,
};
export const expectedExtraParamsC = t.type({
  aNewParam: t.string,
  anotherParam: t.number,
});
