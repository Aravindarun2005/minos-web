package minos.core;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Access structure (M, pi) used by Minos KeyGen (Algorithm 3, lines 1-2).
 *
 * The paper (Section III-C) uses a linear secret-sharing scheme given by a
 * monotone span program M = (F, M, pi) and an injective map
 * pi : [n1] -> U. Algorithm 3 only says "M <- Zp^(n1 x n2)"; a uniformly
 * random matrix does not encode any usable policy, so this class builds M
 * from a boolean policy with the standard Lewko-Waters conversion:
 *
 *   policy := term (OR term)*
 *   term   := factor (AND factor)*
 *   factor := ATTRIBUTE | '(' policy ')'
 *
 * Example: "(Finance AND Manager) OR Admin".
 *
 * A set S satisfies (M, pi) iff there are gamma_i, i in I = pi^-1(S), with
 * sum gamma_i * M_i = (1, 0, ..., 0) - exactly the test in Algorithm 5,
 * line 12 (solved by Authorize.solveGamma).
 *
 * pi must be injective (paper, Algorithm 3 line 2), so every attribute may
 * appear at most once in a policy.
 */
public final class AccessPolicy {

    public final String expression;
    public final Element[][] M;
    public final String[] pi;

    private AccessPolicy(String expression, Element[][] M, String[] pi) {
        this.expression = expression;
        this.M = M;
        this.pi = pi;
    }

    // ------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------

    /** Policy "a1 OR a2 OR ..." - any one listed role is enough. */
    public static AccessPolicy anyOf(Setup.PublicParameters mpk, List<String> roles) {
        if (roles == null || roles.isEmpty()) {
            throw new IllegalArgumentException("Select at least one allowed role");
        }
        return parse(mpk, String.join(" OR ", roles));
    }

    public static AccessPolicy parse(Setup.PublicParameters mpk, String expression) {

        if (expression == null || expression.trim().isEmpty()) {
            throw new IllegalArgumentException("Access policy is empty");
        }

        Parser parser = new Parser(tokenize(expression), mpk.getAttributes());
        Node root = parser.parsePolicy();
        if (parser.pos != parser.tokens.size()) {
            throw new IllegalArgumentException(
                    "Unexpected token in policy: " + parser.tokens.get(parser.pos));
        }

        // Lewko-Waters: label root with (1), counter c = 1.
        Pairing pairing = mpk.getPairing();
        List<int[]> rows = new ArrayList<>();
        List<String> attrs = new ArrayList<>();
        int[] counter = {1};
        assign(root, new int[]{1}, counter, rows, attrs);

        int n1 = rows.size();
        int n2 = counter[0];
        Element[][] M = new Element[n1][n2];

        for (int i = 0; i < n1; i++) {
            int[] r = rows.get(i);
            for (int j = 0; j < n2; j++) {
                int value = j < r.length ? r[j] : 0;
                Element e = pairing.getZr().newElement();
                e.set(value);                 // -1 maps to p - 1 in Zp
                M[i][j] = e.getImmutable();
            }
        }

        return new AccessPolicy(
                canonical(root), M, attrs.toArray(new String[0]));
    }

    /** Rebuilds a policy from its stored expression (deterministic). */
    public static AccessPolicy fromExpression(Setup.PublicParameters mpk, String expression) {
        return parse(mpk, expression);
    }

    // ------------------------------------------------------------
    // Satisfaction (same linear-algebra test as Authorize line 12)
    // ------------------------------------------------------------

    public boolean isSatisfiedBy(Pairing pairing, Set<String> attributes) {
        List<Integer> I = new ArrayList<>();
        for (int i = 0; i < pi.length; i++) {
            if (attributes.contains(pi[i])) I.add(i);
        }
        return !I.isEmpty() && Authorize.solveGamma(pairing, M, I) != null;
    }

    public List<String> attributes() {
        List<String> out = new ArrayList<>();
        for (String a : pi) out.add(a);
        return out;
    }

    // ------------------------------------------------------------
    // Lewko-Waters labelling
    // ------------------------------------------------------------

    private static void assign(Node node, int[] v, int[] c,
                               List<int[]> rows, List<String> attrs) {

        if (node.attribute != null) {
            rows.add(v);
            attrs.add(node.attribute);
            return;
        }

        if (!node.and) {
            for (Node child : node.children) assign(child, v, c, rows, attrs);
            return;
        }

        // AND with k children is handled as a chain of binary ANDs.
        Node left = node.children.get(0);
        Node right;
        if (node.children.size() == 2) {
            right = node.children.get(1);
        } else {
            right = new Node();
            right.and = true;
            right.children.addAll(node.children.subList(1, node.children.size()));
        }

        int len = c[0];
        int[] vl = new int[len + 1];
        System.arraycopy(v, 0, vl, 0, Math.min(v.length, len));
        vl[len] = 1;

        int[] vr = new int[len + 1];
        vr[len] = -1;

        c[0] = len + 1;

        assign(left, vl, c, rows, attrs);
        assign(right, vr, c, rows, attrs);
    }

    // ------------------------------------------------------------
    // Parsing
    // ------------------------------------------------------------

    private static final class Node {
        String attribute;
        boolean and;
        final List<Node> children = new ArrayList<>();
    }

    private static List<String> tokenize(String s) {
        List<String> tokens = new ArrayList<>();
        int i = 0;
        while (i < s.length()) {
            char ch = s.charAt(i);
            if (Character.isWhitespace(ch) || ch == ',') { i++; continue; }
            if (ch == '(' || ch == ')') { tokens.add(String.valueOf(ch)); i++; continue; }
            int j = i;
            while (j < s.length()) {
                char d = s.charAt(j);
                if (Character.isWhitespace(d) || d == '(' || d == ')' || d == ',') break;
                j++;
            }
            tokens.add(s.substring(i, j));
            i = j;
        }
        return tokens;
    }

    private static final class Parser {
        final List<String> tokens;
        final Set<String> universe;
        final Set<String> seen = new LinkedHashSet<>();
        int pos;

        Parser(List<String> tokens, Set<String> universe) {
            this.tokens = tokens;
            this.universe = universe;
        }

        boolean peek(String word) {
            return pos < tokens.size() && tokens.get(pos).equalsIgnoreCase(word);
        }

        Node parsePolicy() {
            Node first = parseTerm();
            if (!peek("OR")) return first;
            Node or = new Node();
            or.children.add(first);
            while (peek("OR")) { pos++; or.children.add(parseTerm()); }
            return or;
        }

        Node parseTerm() {
            Node first = parseFactor();
            if (!peek("AND")) return first;
            Node and = new Node();
            and.and = true;
            and.children.add(first);
            while (peek("AND")) { pos++; and.children.add(parseFactor()); }
            return and;
        }

        Node parseFactor() {
            if (pos >= tokens.size()) throw new IllegalArgumentException("Policy ends unexpectedly");
            String t = tokens.get(pos++);
            if (t.equals("(")) {
                Node inner = parsePolicy();
                if (pos >= tokens.size() || !tokens.get(pos).equals(")")) {
                    throw new IllegalArgumentException("Missing ')' in policy");
                }
                pos++;
                return inner;
            }
            if (t.equals(")") || t.equalsIgnoreCase("AND") || t.equalsIgnoreCase("OR")) {
                throw new IllegalArgumentException("Unexpected '" + t + "' in policy");
            }
            String attribute = resolve(t);
            if (!seen.add(attribute)) {
                // pi must be injective (Algorithm 3, line 2)
                throw new IllegalArgumentException(
                        "Attribute '" + attribute + "' appears twice; pi must be injective");
            }
            Node leaf = new Node();
            leaf.attribute = attribute;
            return leaf;
        }

        String resolve(String token) {
            for (String a : universe) {
                if (a.equalsIgnoreCase(token)) return a;
            }
            throw new IllegalArgumentException(
                    "Unknown attribute '" + token + "'. Universe U = " + universe);
        }
    }

    private static String canonical(Node n) {
        if (n.attribute != null) return n.attribute;
        List<String> parts = new ArrayList<>();
        for (Node c : n.children) {
            String s = canonical(c);
            parts.add(c.attribute == null && c.and != n.and ? "(" + s + ")" : s);
        }
        return String.join(n.and ? " AND " : " OR ", parts);
    }

    @Override
    public String toString() {
        return expression;
    }
}
