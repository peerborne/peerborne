/** Compare already authenticated opaque digest strings for one authority. */
function classifyAuthorityVote(
  previous: string | undefined,
  incoming: string,
): 'new' | 'duplicate' | 'equivocation' {
  //@ verify
  //@ ensures \result === "new" <==> previous === undefined
  if (previous === undefined) return 'new';
  return previous === incoming ? 'duplicate' : 'equivocation';
}

export interface AuthorityVote {
  readonly authority: string;
  readonly digest: string;
}

export interface AuthorityVoteClassification {
  readonly firstVotes: boolean[];
  readonly equivocating: boolean;
}

/** Classify detached, authenticated votes without transport or crypto effects. */
export function classifyAuthorityVotes(
  votes: readonly AuthorityVote[],
): AuthorityVoteClassification {
  //@ verify
  //@ requires votes.length <= 4294967295
  //@ ensures \result.firstVotes.length === votes.length
  //@ ensures forall(j: int, 0 <= j && j < votes.length ==> (\result.firstVotes[j] <==> forall(k: int, 0 <= k && k < j ==> votes[k].authority !== votes[j].authority)))
  //@ ensures \result.equivocating <==> exists(a: int, exists(b: int, 0 <= a && a < b && b < votes.length && votes[a].authority === votes[b].authority && votes[a].digest !== votes[b].digest))
  const seen = new Map<string, string>();
  const firstVotes: boolean[] = [];
  let equivocating = false;
  for (let index = 0; index < votes.length; index++) {
    //@ invariant 0 <= index && index <= votes.length
    //@ invariant firstVotes.length === index
    //@ invariant forall(j: int, 0 <= j && j < index ==> seen.has(votes[j].authority))
    //@ invariant forall(key: string, seen.has(key) ==> exists(j: int, 0 <= j && j < index && votes[j].authority === key && votes[j].digest === seen[key]))
    //@ invariant !equivocating ==> forall(j: int, 0 <= j && j < index ==> seen[votes[j].authority] === votes[j].digest)
    //@ invariant equivocating ==> exists(a: int, exists(b: int, 0 <= a && a < b && b < index && votes[a].authority === votes[b].authority && votes[a].digest !== votes[b].digest))
    //@ invariant forall(j: int, 0 <= j && j < index ==> (firstVotes[j] <==> forall(k: int, 0 <= k && k < j ==> votes[k].authority !== votes[j].authority)))
    //@ decreases votes.length - index
    const vote = votes[index];
    const disposition = classifyAuthorityVote(
      seen.get(vote.authority),
      vote.digest,
    );
    if (disposition === 'new') {
      seen.set(vote.authority, vote.digest);
      firstVotes.push(true);
    } else {
      firstVotes.push(false);
      if (disposition === 'equivocation') equivocating = true;
    }
  }
  return { firstVotes, equivocating };
}
