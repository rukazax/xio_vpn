package app.xio.xio;
public final class ReviewMissingHandshake {
  public static void main(String[] args) throws Exception {
    int failures=0;
    for(long started: new long[]{0,1000,2000}) for(long missing: new long[]{0,-1,-2,-3}) {
      long[] mono={0}; int[] http={0}; boolean accepted=false;
      ConnectionBudget budget=new ConnectionBudget(1000,()->mono[0]);
      try {
        BackgroundVerificationOptions.fromPlanValue(false).verify(started,budget,
          left->{http[0]++;},()->missing,left->{mono[0]+=left;});
        accepted=true;
      } catch(ConnectionBudget.Expired expected) {}
      if(http[0]!=0) throw new AssertionError("opt-out HTTP");
      System.out.println("started="+started+" missing="+missing+" accepted="+accepted);
      if(accepted) failures++;
    }
    if(failures!=0) throw new AssertionError("Missing/nonpositive handshake accepted in "+failures+" cases");
  }
}
