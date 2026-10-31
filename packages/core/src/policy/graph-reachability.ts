export interface CidEdge {
  readonly from: string;
  readonly to: string;
}

/** Least successor-closed set containing root in a bounded, decoded graph. */
export function reachableCids(
  nodes: readonly string[],
  edges: readonly CidEdge[],
  root: string,
): Set<string> {
  //@ verify
  //@ requires nodes.length <= 32768 && edges.length <= 131072
  //@ requires nodes.includes(root)
  //@ requires forall(i: int, 0 <= i && i < edges.length ==> nodes.includes(edges[i].from) && nodes.includes(edges[i].to))
  //@ ensures \result.has(root)
  //@ ensures forall(key: string, \result.has(key) ==> nodes.includes(key))
  //@ ensures forall(i: int, 0 <= i && i < edges.length && \result.has(edges[i].from) ==> \result.has(edges[i].to))
  const adjacency = new Map<string, string[]>();
  for (let edgeIndex = 0; edgeIndex < edges.length; edgeIndex++) {
    //@ invariant 0 <= edgeIndex && edgeIndex <= edges.length
    //@ invariant forall(key: string, adjacency.has(key) ==> nodes.includes(key) && adjacency.get(key).length <= edgeIndex)
    //@ invariant forall(i: int, 0 <= i && i < edgeIndex ==> adjacency.has(edges[i].from) && adjacency.get(edges[i].from).includes(edges[i].to))
    //@ decreases edges.length - edgeIndex
    const edge = edges[edgeIndex];
    const children = adjacency.get(edge.from) ?? [];
    children.push(edge.to);
    adjacency.set(edge.from, children);
  }
  const seen = new Set<string>();
  const queue = [root];
  let index = 0;
  let enqueuedEdges = 0;
  while (index < queue.length) {
    //@ invariant 0 <= index && index <= queue.length
    //@ invariant seen.size <= nodes.length
    //@ invariant 0 <= enqueuedEdges && enqueuedEdges <= edges.length
    //@ invariant queue.length <= edges.length + 1
    //@ invariant queue.includes(root)
    //@ invariant forall(j: int, 0 <= j && j < queue.length ==> nodes.includes(queue[j]))
    //@ invariant forall(key: string, seen.has(key) ==> nodes.includes(key))
    //@ invariant forall(j: int, 0 <= j && j < index ==> seen.has(queue[j]))
    //@ invariant forall(i: int, 0 <= i && i < edges.length && seen.has(edges[i].from) ==> queue.includes(edges[i].to))
    //@ decreases nodes.length - seen.size + edges.length - enqueuedEdges + queue.length - index
    const node = queue[index];
    index++;
    if (seen.has(node)) continue;
    seen.add(node);
    const children = adjacency.get(node) ?? [];
    enqueuedEdges += children.length;
    for (let child = 0; child < children.length; child++) {
      //@ invariant 0 <= child && child <= children.length
      //@ invariant forall(j: int, 0 <= j && j < child ==> queue.includes(children[j]))
      //@ invariant queue.includes(root)
      //@ invariant index <= queue.length
      //@ invariant seen.size <= nodes.length
      //@ invariant 0 <= enqueuedEdges && enqueuedEdges <= edges.length
      //@ invariant queue.length <= edges.length + 1
      //@ invariant forall(j: int, 0 <= j && j < queue.length ==> nodes.includes(queue[j]))
      //@ invariant forall(j: int, 0 <= j && j < index ==> seen.has(queue[j]))
      //@ invariant forall(i: int, 0 <= i && i < edges.length && seen.has(edges[i].from) && edges[i].from !== node ==> queue.includes(edges[i].to))
      //@ decreases children.length - child
      queue.push(children[child]);
    }
  }
  return seen;
}

export function shouldPruneDocumentChildren(
  isAcl: boolean,
  documentNodesVisited: number,
  keepCount: number,
): boolean {
  //@ verify
  //@ ensures \result <==> !isAcl && documentNodesVisited >= keepCount
  //@ ensures isAcl ==> !\result
  return !isAcl && documentNodesVisited >= keepCount;
}
