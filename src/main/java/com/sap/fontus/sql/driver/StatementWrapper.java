package com.sap.fontus.sql.driver;


import com.sap.fontus.sql.tainter.StatementTainter;
import com.sap.fontus.sql.tainter.Taint;
import net.sf.jsqlparser.JSQLParserException;
import net.sf.jsqlparser.parser.CCJSqlParserUtil;
import net.sf.jsqlparser.statement.Statements;


import java.sql.*;
import java.util.ArrayList;
import java.util.List;


public class StatementWrapper extends AbstractWrapper implements Statement {

    private static final String LINE_SEPARATOR = System.getProperty("line.separator");
    private final Statement delegate;

    public static Statement wrap(Statement delegate) {
        if (delegate == null) {
            return null;
        }
        return new StatementWrapper(delegate);
    }

    protected StatementWrapper(Statement delegate) {
        super(delegate);
        this.delegate = delegate;
    }

    @Override
    public ResultSet getResultSet() throws SQLException {
        return ResultSetWrapper.wrap(delegate.getResultSet());
    }

    @Override
    public ResultSet executeQuery(String sql) throws SQLException {
        sql = parseSql(sql);
        return ResultSetWrapper.wrap(delegate.executeQuery(sql));
    }

    @Override
    public int[] executeBatch() throws SQLException {
        return delegate.executeBatch();
    }

    @Override
    public boolean execute(String sql) throws SQLException {
        sql = parseSql(sql);
        return delegate.execute(sql);
    }

    @Override
    public boolean execute(String sql, int autoGeneratedKeys) throws SQLException {
        sql = parseSql(sql);
        return delegate.execute(sql, autoGeneratedKeys);
    }

    @Override
    public boolean execute(String sql, int[] columnIndexes) throws SQLException {
        sql = parseSql(sql);
        for(int i = 0; i < columnIndexes.length;i++){
            columnIndexes[i]= (columnIndexes[i]*2)-1;
        }
        return delegate.execute(sql, columnIndexes);
    }

    @Override
    public boolean execute(String sql, String[] columnNames) throws SQLException {
        sql = parseSql(sql);
        return delegate.execute(sql, columnNames);
    }

    @Override
    public int executeUpdate(String sql) throws SQLException {
        sql = parseSql(sql);
        return delegate.executeUpdate(sql);
    }

    @Override
    public int executeUpdate(String sql, int autoGeneratedKeys) throws SQLException {
        sql = parseSql(sql);
        return delegate.executeUpdate(sql, autoGeneratedKeys);
    }

    @Override
    public int executeUpdate(String sql, int[] columnIndexes) throws SQLException {
        sql = parseSql(sql);
        for(int i = 0; i < columnIndexes.length;i++){
            columnIndexes[i]= (columnIndexes[i]*2)-1;
        }
        return delegate.executeUpdate(sql, columnIndexes);
    }

    @Override
    public int executeUpdate(String sql, String[] columnNames) throws SQLException {
        sql = parseSql(sql);
        return delegate.executeUpdate(sql, columnNames);
    }

    @Override
    public void addBatch(String sql) throws SQLException {
        sql = parseSql(sql);
        delegate.addBatch(sql);
    }

    @Override
    public void close() throws SQLException {
        delegate.close();
    }

    @Override
    public int getMaxFieldSize() throws SQLException {
        return delegate.getMaxFieldSize();
    }

    @Override
    public void setMaxFieldSize(int max) throws SQLException {
        delegate.setMaxFieldSize(max);
    }

    @Override
    public int getMaxRows() throws SQLException {
        return delegate.getMaxRows();
    }

    @Override
    public void setMaxRows(int max) throws SQLException {
        delegate.setMaxRows(max);
    }

    @Override
    public void setEscapeProcessing(boolean enable) throws SQLException {
        delegate.setEscapeProcessing(enable);
    }

    @Override
    public int getQueryTimeout() throws SQLException {
        return delegate.getQueryTimeout();
    }

    @Override
    public void setQueryTimeout(int seconds) throws SQLException {
        delegate.setQueryTimeout(seconds);
    }

    @Override
    public void cancel() throws SQLException {
        delegate.cancel();
    }

    @Override
    public SQLWarning getWarnings() throws SQLException {
        return delegate.getWarnings();
    }

    @Override
    public void clearWarnings() throws SQLException {
        delegate.clearWarnings();
    }

    @Override
    public void setCursorName(String name) throws SQLException {
        delegate.setCursorName(name);
    }

    @Override
    public int getUpdateCount() throws SQLException {
        return delegate.getUpdateCount();
    }

    @Override
    public boolean getMoreResults() throws SQLException {
        return delegate.getMoreResults();
    }

    @Override
    public void setFetchDirection(int direction) throws SQLException {
        delegate.setFetchDirection(direction);
    }

    @Override
    public int getFetchDirection() throws SQLException {
        return delegate.getFetchDirection();
    }

    @Override
    public void setFetchSize(int rows) throws SQLException {
        delegate.setFetchSize(rows);
    }

    @Override
    public int getFetchSize() throws SQLException {
        return delegate.getFetchSize();
    }

    @Override
    public int getResultSetConcurrency() throws SQLException {
        return delegate.getResultSetConcurrency();
    }

    @Override
    public int getResultSetType() throws SQLException {
        return delegate.getResultSetType();
    }

    @Override
    public void clearBatch() throws SQLException {
        delegate.clearBatch();
    }

    @Override
    public Connection getConnection() throws SQLException {
        return delegate.getConnection();
    }

    @Override
    public boolean getMoreResults(int current) throws SQLException {
        return delegate.getMoreResults(current);
    }

    @Override
    public ResultSet getGeneratedKeys() throws SQLException {
        return ResultSetWrapper.wrap(delegate.getGeneratedKeys());
    }

    @Override
    public int getResultSetHoldability() throws SQLException {
        return delegate.getResultSetHoldability();
    }

    @Override
    public boolean isClosed() throws SQLException {
        return delegate.isClosed();
    }

    @Override
    public void setPoolable(boolean poolable) throws SQLException {
        delegate.setPoolable(poolable);
    }

    @Override
    public boolean isPoolable() throws SQLException {
        return delegate.isPoolable();
    }

    @Override
    public void closeOnCompletion() throws SQLException {
        delegate.closeOnCompletion();
    }

    @Override
    public boolean isCloseOnCompletion() throws SQLException {
        return delegate.isCloseOnCompletion();
    }

    public String parseSql(String sql){
        List<Taint> taints = new ArrayList<>();
        StatementTainter tainter = new StatementTainter(taints);
        //TODO: cleaner implementation of stmts
        Statements stmts=null;
        try {
            stmts = CCJSqlParserUtil.parseStatements(sql);
            stmts.accept(tainter);
        } catch (JSQLParserException jsqlParserException) {
            jsqlParserException.printStackTrace();
        }
        System.out.println((stmts.toString().trim()));
        return stmts.toString().trim();
    }
}

