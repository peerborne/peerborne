const POWERS_OF_TWO = [
  1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768,
  65536, 131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216,
  33554432, 67108864, 134217728, 268435456, 536870912, 1073741824, 2147483648,
] as const;
Object.freeze(POWERS_OF_TWO);

export function powerOfTwo(exponent: number): number {
  //@ verify
  //@ requires 0 <= exponent && exponent <= 31
  //@ ensures 1 <= \result && \result <= 2147483648
  //@ ensures exponent === 0 ==> \result === 1
  //@ ensures exponent === 30 ==> \result === 1073741824
  //@ ensures exponent === 31 ==> \result === 2147483648
  //@ ensures exponent <= 30 ==> \result <= 1073741824
  //@ ensures exponent > 0 ==> \result === 2 * powerOfTwo(exponent - 1)
  return POWERS_OF_TWO[exponent];
}

export function nodeLevel(index: number): number {
  //@ verify
  //@ requires 0 <= index && index <= 2147483646
  //@ ensures 0 <= \result && \result <= 30
  //@ ensures \result === 0 <==> index % 2 === 0
  //@ ensures powerOfTwo(\result) <= index + 1
  //@ ensures (index + 1) % powerOfTwo(\result) === 0
  //@ ensures Math.floor((index + 1) / powerOfTwo(\result)) % 2 === 1
  //@ decreases index
  return index % 2 === 0 ? 0 : nodeLevel(Math.floor((index - 1) / 2)) + 1;
}

export function floorLog2(value: number): number {
  //@ verify
  //@ requires 1 <= value && value <= 2147483647
  //@ ensures 0 <= \result && \result <= 30
  //@ ensures powerOfTwo(\result) <= value && value < 2 * powerOfTwo(\result)
  //@ decreases value
  return value < 2 ? 0 : floorLog2(Math.floor(value / 2)) + 1;
}

export function treeWidth(leaves: number): number {
  //@ verify
  //@ requires 1 <= leaves && leaves <= 1073741824
  //@ ensures \result === 2 * leaves - 1
  //@ ensures 1 <= \result && \result <= 2147483647
  return 2 * leaves - 1;
}

export function treeRoot(leaves: number): number {
  //@ verify
  //@ requires 1 <= leaves && leaves <= 1073741824
  //@ ensures 0 <= \result && \result < treeWidth(leaves)
  //@ ensures \result + 1 <= treeWidth(leaves) && treeWidth(leaves) < 2 * (\result + 1)
  //@ ensures \result === powerOfTwo(floorLog2(treeWidth(leaves))) - 1
  //@ ensures nodeLevel(\result) === floorLog2(treeWidth(leaves))
  return powerOfTwo(floorLog2(treeWidth(leaves))) - 1;
}

export function leafNodeIndex(position: number): number {
  //@ verify
  //@ requires 0 <= position && position < 1073741824
  //@ ensures \result === position * 2 && \result % 2 === 0
  //@ ensures 0 <= \result && \result <= 2147483646
  //@ ensures Math.floor(\result / 2) === position
  return position * 2;
}

export function leafPosition(index: number): number {
  //@ verify
  //@ requires 0 <= index && index <= 2147483646 && index % 2 === 0
  //@ ensures 0 <= \result && \result < 1073741824
  //@ ensures 2 * \result === index
  return Math.floor(index / 2);
}

export function leftChild(index: number): number {
  //@ verify
  //@ requires 0 <= index && index <= 2147483646 && nodeLevel(index) > 0
  //@ ensures 0 <= \result && \result < index
  //@ ensures nodeLevel(\result) === nodeLevel(index) - 1
  //@ ensures \result === index - powerOfTwo(nodeLevel(index) - 1)
  const exponent = nodeLevel(index);
  return index - powerOfTwo(exponent - 1);
}

export function rightChild(index: number): number {
  //@ verify
  //@ requires 0 <= index && index <= 2147483646 && nodeLevel(index) > 0
  //@ ensures index < \result && \result <= 2147483646
  //@ ensures nodeLevel(\result) === nodeLevel(index) - 1
  //@ ensures \result === index + powerOfTwo(nodeLevel(index) - 1)
  //@ ensures \result - powerOfTwo(nodeLevel(\result)) + 1 === index + 1
  const exponent = nodeLevel(index);
  return index + powerOfTwo(exponent - 1);
}

export function clampRightChild(index: number, width: number): number {
  //@ verify
  //@ requires 0 <= index && index <= 2147483646
  //@ requires 1 <= width && width <= 2147483647
  //@ requires index - powerOfTwo(nodeLevel(index)) + 1 < width
  //@ ensures 0 <= \result && \result < width && \result <= index
  //@ ensures nodeLevel(\result) <= nodeLevel(index)
  //@ ensures index - powerOfTwo(nodeLevel(index)) + 1 <= \result
  //@ decreases nodeLevel(index)
  return index < width ? index : clampRightChild(leftChild(index), width);
}

export function parentStep(index: number): number {
  //@ verify
  //@ requires 0 <= index && index <= 2147483646 && nodeLevel(index) < 30
  //@ ensures 0 <= \result && \result <= 2147483646
  //@ ensures nodeLevel(\result) === nodeLevel(index) + 1
  const exponent = nodeLevel(index);
  const step = powerOfTwo(exponent);
  const higherBit = Math.floor(index / (2 * step)) % 2;
  return higherBit === 0 ? index + step : index - step;
}

export function parentInWidth(
  index: number,
  width: number,
  rootLevel: number,
): number {
  //@ verify
  //@ requires 0 <= rootLevel && rootLevel <= 30
  //@ requires powerOfTwo(rootLevel) <= width && width < 2 * powerOfTwo(rootLevel)
  //@ requires 0 <= index && index < 2 * powerOfTwo(rootLevel) - 1
  //@ requires nodeLevel(index) < rootLevel
  //@ ensures 0 <= \result && \result < width
  //@ ensures nodeLevel(index) < nodeLevel(\result) && nodeLevel(\result) <= rootLevel
  //@ decreases rootLevel - nodeLevel(index)
  const next = parentStep(index);
  return next < width ? next : parentInWidth(next, width, rootLevel);
}

export function treeParent(index: number, leaves: number): number {
  //@ verify
  //@ requires 1 <= leaves && leaves <= 1073741824
  //@ requires 0 <= index && index < treeWidth(leaves) && index !== treeRoot(leaves)
  //@ ensures 0 <= \result && \result < treeWidth(leaves)
  //@ ensures nodeLevel(\result) > nodeLevel(index)
  return parentInWidth(index, treeWidth(leaves), floorLog2(treeWidth(leaves)));
}

export function treeRight(index: number, leaves: number): number {
  //@ verify
  //@ requires 1 <= leaves && leaves <= 1073741824
  //@ requires 0 <= index && index < treeWidth(leaves) && nodeLevel(index) > 0
  //@ ensures 0 <= \result && \result < treeWidth(leaves)
  //@ ensures nodeLevel(\result) < nodeLevel(index)
  //@ ensures index < \result
  return clampRightChild(rightChild(index), treeWidth(leaves));
}

export function treeSibling(index: number, leaves: number): number {
  //@ verify
  //@ requires 1 <= leaves && leaves <= 1073741824
  //@ requires 0 <= index && index < treeWidth(leaves) && index !== treeRoot(leaves)
  //@ ensures 0 <= \result && \result < treeWidth(leaves)
  //@ ensures \result !== index
  const parent = treeParent(index, leaves);
  return leftChild(parent) === index
    ? treeRight(parent, leaves)
    : leftChild(parent);
}

export function treeDirectPath(index: number, leaves: number): number[] {
  //@ verify
  //@ requires 1 <= leaves && leaves <= 1073741824
  //@ requires 0 <= index && index < treeWidth(leaves)
  //@ ensures \result.length <= 30 - nodeLevel(index)
  //@ ensures index === treeRoot(leaves) <==> \result.length === 0
  //@ ensures \result.length > 0 ==> \result[0] === treeParent(index, leaves)
  //@ ensures forall(i: int, 0 <= i && i < \result.length ==> 0 <= \result[i] && \result[i] < treeWidth(leaves) && nodeLevel(\result[i]) > nodeLevel(index))
  //@ ensures forall(i: int, 0 <= i && i + 1 < \result.length ==> \result[i] !== treeRoot(leaves))
  //@ ensures forall(i: int, 0 <= i && i + 1 < \result.length ==> \result[i + 1] === treeParent(\result[i], leaves))
  //@ ensures \result.length > 0 ==> \result[\result.length - 1] === treeRoot(leaves)
  //@ decreases 30 - nodeLevel(index)
  if (index === treeRoot(leaves)) return [];
  const parent = treeParent(index, leaves);
  return [parent, ...treeDirectPath(parent, leaves)];
}

export function treeCopath(index: number, leaves: number): number[] {
  //@ verify
  //@ requires 1 <= leaves && leaves <= 1073741824
  //@ requires 0 <= index && index < treeWidth(leaves)
  //@ ensures \result.length === treeDirectPath(index, leaves).length && \result.length <= 30
  //@ ensures forall(i: int, 0 <= i && i < \result.length ==> 0 <= \result[i] && \result[i] < treeWidth(leaves))
  //@ ensures \result.length > 0 ==> \result[0] === treeSibling(index, leaves)
  //@ ensures forall(i: int, 0 < i && i < \result.length ==> \result[i] === treeSibling(treeDirectPath(index, leaves)[i - 1], leaves))
  //@ decreases 30 - nodeLevel(index)
  if (index === treeRoot(leaves)) return [];
  return [
    treeSibling(index, leaves),
    ...treeCopath(treeParent(index, leaves), leaves),
  ];
}
